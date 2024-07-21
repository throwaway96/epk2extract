/**
 * Copyright 2016 Smx <smxdev4@gmail.com>
 * All right reserved
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <assert.h>

#include "main.h"
#include "config.h"
#include "mfile.h"
#include "epk3.h"
#include "util.h"
#include "util_crypto.h"

/*
 * Check for epk3 files with an additional heading signature (whole file signature?)
 */
bool compare_epk3_new_header(const uint8_t *header, size_t headerSize){
	const EPK_V3_HEADER_T *hdr = (const EPK_V3_HEADER_T *)(header + SIGNATURE_SIZE);
	return memcmp(hdr->epkMagic, EPK3_MAGIC, sizeof(hdr->epkMagic)) == 0;
}

/*
 * Checks if the given data is an EPK3 header
 */
bool compare_epk3_header(const uint8_t *header, size_t headerSize){
	const EPK_V3_HEADER_T *hdr = (const EPK_V3_HEADER_T *)header;

	return memcmp(hdr->epkMagic, EPK3_MAGIC, sizeof(hdr->epkMagic)) == 0;
}

MFILE *isFileEPK3(const char *epk_file) {
	setKeyFile_LG();
	MFILE *file = mopen(epk_file, O_RDONLY);
	if (!file) {
		err_exit("Can't open file %s\n\n", epk_file);
	}

	struct epk3_structure *epk3 = mdata(file, struct epk3_structure);
	struct epk3_head_structure *head = &(epk3->head);

	if(msize(file) < sizeof(*epk3)){
		goto checkFail;
	}

	// check if the epk magic is present (decrypted)
	if(compare_epk3_header((uint8_t *)&(head->epkHeader), sizeof(EPK_V3_HEADER_T))){
		goto checkOk;
	}

	if(isEpkVersionString(head->platformVersion) && isEpkVersionString(head->sdkVersion))
		goto checkOk;


	checkFail:
		mclose(file);
		return NULL;

	checkOk:
		printf("[EPK3] Platform Version: %.*s\n", int_sizeof(head->platformVersion), head->platformVersion);
		printf("[EPK3] SDK Version: %.*s\n", int_sizeof(head->sdkVersion), head->sdkVersion);
		return file;
}

void extractEPK3(MFILE *epk, FILE_TYPE_T epkType, config_opts_t *config_opts){

	epk3_union *epk3 = mdata(epk, epk3_union);

	size_t headerSize, signed_size, sigSize;
	size_t extraSegmentSize; /* size of additional data in new format */
	SIG_TYPE_T sigType;
	switch(epkType){
		case EPK_V3:
			headerSize = sizeof(EPK_V3_HEADER_T);
			signed_size = (
				sizeof(epk3->old.head.epkHeader) +
				sizeof(epk3->old.head.crc32Info) +
				sizeof(epk3->old.head.reserved)
			);
			sigType = SIG_SHA1;
			sigSize = SIGNATURE_SIZE;
			extraSegmentSize = 0;
			break;
		case EPK_V3_NEW:
			headerSize = sizeof(EPK_V3_NEW_HEADER_T);
			signed_size = headerSize;
			sigType = SIG_SHA256;
			sigSize = SIGNATURE_SIZE_NEW;
			/* each segment has an index value */
			extraSegmentSize = sizeof(uint32_t);
			break;
		default:
			err_exit("Unsupported EPK3 variant\n");
	}

	EPK_V3_HEADER_UNION *epkHeader;

	if (epkType == EPK_V3_NEW) {
		epkHeader = (EPK_V3_HEADER_UNION *) &(epk3->new.head.epkHeader);
	} else {
		epkHeader = (EPK_V3_HEADER_UNION *) &(epk3->old.head.epkHeader);
	}

	if(config_opts->enableSignatureChecking)
	{
		wrap_verifyimage(
			epk3->old.head.signature,	/* same offset in old/new */
			epkHeader,
			signed_size,
			config_opts->config_dir,
			sigType
		);
	}

	if (!wrap_decryptimage(
		epkHeader,
		headerSize,
		epkHeader,
		config_opts->dest_dir,
		EPK_V3,
		NULL
	)) {
		return;
	}

	size_t pak_signed_size;
	PAK_V3_LISTHEADER_UNION *packageInfo;

	PAK_V3_HEADER_T *pak;

	const void *pkgInfoSigPtr;

	switch(epkType){
		case EPK_V3:
			pak_signed_size = epkHeader->old.packageInfoSize;
			packageInfo = (PAK_V3_LISTHEADER_UNION *) &(epk3->old.packageInfo);
			pak = &(packageInfo->old.packages[0]);
			pkgInfoSigPtr = epk3->old.packageInfo_signature;
			break;
		case EPK_V3_NEW:
			pak_signed_size = epkHeader->new.packageInfoSize;
			packageInfo = (PAK_V3_LISTHEADER_UNION *) &(epk3->new.packageInfo);
			pak = &(packageInfo->new.packages[0]);
			pkgInfoSigPtr = epk3->new.packageInfo_signature;
			break;
		default:
			err_exit("Unsupported EPK3 variant\n");
	}

	if(config_opts->enableSignatureChecking){
		wrap_verifyimage(
			pkgInfoSigPtr,
			packageInfo,
			pak_signed_size,
			config_opts->config_dir,
			sigType
		);
	}

	printf("\nFirmware info\n");
	printf("-------------\n");
	printf("Firmware magic: %.*s\n", 4, epkHeader->old.epkMagic);
	printf("Firmware otaID: %s\n", epkHeader->old.otaId);
	printf("Firmware version: " EPK_VERSION_FORMAT "\n",
		epkHeader->old.epkVersion[3],
		epkHeader->old.epkVersion[2],
		epkHeader->old.epkVersion[1],
		epkHeader->old.epkVersion[0]
	);
	printf("packageInfoSize: %" PRIu32 "\n", epkHeader->old.packageInfoSize);
	printf("bChunked: %" PRIu32 "\n", epkHeader->old.bChunked);

	if(epkType == EPK_V3_NEW){
		printf("EncryptType: %.*s\n",
			int_sizeof(epkHeader->new.encryptType),
			epkHeader->new.encryptType
		);
		printf("UpdateType:  %.*s\n",
			int_sizeof(epkHeader->new.updateType),
			epkHeader->new.updateType
		);
		printf("unknown: %02hhx %02hhx %02hhx\n", epkHeader->new.gap[0], epkHeader->new.gap[1], epkHeader->new.gap[2]);
		printf("updatePlatformVersion: %f\n", epkHeader->new.updatePlatformVersion);
		printf("compatibleMinimumVersion: %f\n", epkHeader->new.compatibleMinimumVersion);
		printf("needToCheckCompatibleVersion: %d\n", epkHeader->new.needToCheckCompatibleVersion);
	}

	if (config_opts->signatureOnly)
		return;

	char *fwVersion;
	asprintf(&fwVersion, EPK_VERSION_FORMAT "-%s",
		epkHeader->old.epkVersion[3],
		epkHeader->old.epkVersion[2],
		epkHeader->old.epkVersion[1],
		epkHeader->old.epkVersion[0],
		epkHeader->old.otaId
	);

	asprintf_inplace(&config_opts->dest_dir, "%s/%s", config_opts->dest_dir, fwVersion);

	createFolder(config_opts->dest_dir);
	free(fwVersion);

	printf("---- begin ----\n");

	/* Decrypt packageInfo */
	if (!wrap_decryptimage(
		packageInfo,
		epkHeader->old.packageInfoSize,
		packageInfo,
		config_opts->dest_dir,
		RAW,
		NULL
	)) {
		return;
	}

	if(epkType == EPK_V3_NEW){
		if(packageInfo->new.pakInfoMagic != epkHeader->new.pakInfoMagic){
			printf("pakInfoMagic mismatch! (expected: %04" PRIX32 ", actual: %04" PRIX32 ")\n",
					epkHeader->new.pakInfoMagic,
					packageInfo->new.pakInfoMagic
			);
			return;
		}
	}

	/* These fields have the same offests in the old and new formats. */
	uintptr_t dataPtr = (uintptr_t)packageInfo + epkHeader->old.packageInfoSize;
	const uint_least32_t packageInfoCount = packageInfo->old.packageInfoCount;

	for (unsigned int packageInfoIndex = 0; packageInfoIndex < packageInfoCount; /* handled elsewhere */) {
		if(pak->packageInfoSize != sizeof(*pak)){
			printf("Warning: Unexpected packageInfoSize '%" PRIu32 "', expected '%zu'\n",
					pak->packageInfoSize, sizeof(*pak)
			);
		}

		const char *const pakName = pak->packageName;

		printf("\nPAK '%s' contains %" PRIu32 " segment%s, size %" PRIu32 " bytes:\n",
			pakName,
			pak->segmentInfo.segmentCount,
			(pak->segmentInfo.segmentCount == 1) ? "" : "s",
			pak->packageSize
		);

		char *pakFileName = NULL;
		MFILE *pakFile = NULL;

		if (asprintf(&pakFileName, "%s/%s.pak", config_opts->dest_dir, pakName) == -1) {
			err_exit("Error creating output filename for partition '%s'\n", pakName);
		}

		if ((pakFile = mfopen(pakFileName, "w+")) == NULL) {
			err_exit("Cannot open file '%s' for writing\n", pakFileName);
		}

		mfile_map(pakFile, pak->packageSize);
		printf("Saving partition '%s' to file '%s'\n", pakName, pakFileName);

		unsigned int curSegmentIndex = packageInfoIndex;
		PACKAGE_SEGMENT_INFO_T segmentInfo = pak->segmentInfo;
		for (uint_least32_t segNo = segmentInfo.segmentIndex;
			segNo < segmentInfo.segmentCount;
			segNo++, pak++, curSegmentIndex++
		) {
			const void *dataSigPtr = (void *) dataPtr;
			dataPtr += sigSize;

			if(config_opts->enableSignatureChecking)
			{
				wrap_verifyimage(
					dataSigPtr,
					(const void *)dataPtr,
					pak->segmentInfo.segmentSize + extraSegmentSize,
					config_opts->config_dir,
					sigType
				);
			}

			printf("  segment #%" PRIuLEAST32 " (name='%s', version='%s', offset='0x%jx', size='%" PRIu32 " bytes')\n",
				segNo + 1,
				pakName,
				pak->packageVersion,
				(intmax_t) moff(epk, dataPtr),
				pak->segmentInfo.segmentSize
			);

			if (!wrap_decryptimage(
					(void *)dataPtr,
					pak->segmentInfo.segmentSize,
					(void *)dataPtr,
					config_opts->dest_dir,
					RAW,
					NULL
			)) {
				return;
			}

			if(epkType == EPK_V3_NEW){
				uint_least32_t decryptedSegmentIndex = *(uint32_t *)dataPtr;
				if(decryptedSegmentIndex != curSegmentIndex){
					printf("Warning: Decrypted segment doesn't match expected index! (index: %" PRIuLEAST32 ", expected: %u)\n",
							decryptedSegmentIndex, curSegmentIndex
					);
				}
			}

			/* advance past segment index in new EPK3 format */
			dataPtr += extraSegmentSize;

			mwrite(dataPtr, pak->segmentInfo.segmentSize, 1, pakFile);

			dataPtr += pak->segmentInfo.segmentSize;
		}

		mclose(pakFile);
		pakFile = NULL;

		handle_file(pakFileName, config_opts);
		free(pakFileName);
		pakFileName = NULL;

		packageInfoIndex = curSegmentIndex;
	}
}
