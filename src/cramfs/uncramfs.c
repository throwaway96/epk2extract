//
// Uncramfs
// A program to unpack a cramfs image
//
// Copyright Andrew Stitcher, 2001
//
// Licensed according to the GNU GPL v2
//

// C things
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Unix things
#include <unistd.h>
#include <errno.h>
//#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/fcntl.h>
#ifndef __APPLE__
#    include <sys/sysmacros.h>
#endif

// Application libraries
#include <zlib.h>

// Cramfs definitions
#include "cramfs.h"

#include "os_byteswap.h"

#define PAGE_CACHE_SIZE (4096)

/* The kernel assumes PAGE_CACHE_SIZE as block size. */
static unsigned long blksize = PAGE_CACHE_SIZE;

static char *opt_devfile = NULL;
static char *opt_idsfile = NULL;

static int DIR_GID = 0;

void do_file_entry(const u8 * base, const char *dir, const char *path, const char *name, int namelen, const struct cramfs_inode *inode);

void do_dir_entry(const u8 * base, const char *dir, const char *path, const char *name, int namelen, const struct cramfs_inode *inode);

///////////////////////////////////////////////////////////////////////////////

u32 compressed_size(const u8 * base, const u8 * data, u32 size) {
	const u32 *buffs = (const u32 *)(data);
	int nblocks = (size - 1) / blksize + 1;
	const u8 *buffend = base + *(buffs + nblocks - 1);

	if (size == 0)
		return 0;
	else
		return buffend - data;
}

void uncompress_data(const u8 * base, const u8 * data, u32 size, u8 * dstdata) {
	const u32 *buffs = (const u32 *)(data);
	int nblocks = (size - 1) / blksize + 1;
	const u8 *buff = (const u8 *)(buffs + nblocks);
	const u8 *nbuff;
	int block = 0;
	uLongf len = size;

	if (size == 0) {
		return;
	}

	for (; block < nblocks; ++block, buff = nbuff, dstdata += blksize, len -= blksize) {
		uLongf tran = (len < blksize) ? len : blksize;
		nbuff = base + *(buffs + block);
		if (uncompress(dstdata, &tran, buff, nbuff - buff) != Z_OK) {
			fprintf(stderr, "Uncompression failed");
			return;
		}
	}
}

///////////////////////////////////////////////////////////////////////////////

int stats_totalsize;
int stats_totalcsize;
int stats_count;
int stats_compresses;
int stats_expands;

void clearstats() {
	stats_totalsize = 0;
	stats_totalcsize = 0;
	stats_count = 0;
	stats_compresses = 0;
	stats_expands = 0;
}

void updatestats(int size, int csize) {
	++stats_count;
	stats_totalsize += size;
	stats_totalcsize += csize;

	if (size >= csize) {
		stats_compresses++;
	} else {
		stats_expands++;
	}
}

void printstats() {
	printf("\n[Summary:]\n");
	printf("[Total uncompressed size:    %9d]\n", stats_totalsize);
	printf("[Total compressed size:      %9d]\n", stats_totalcsize);
	printf("[Number of entries:          %9d]\n", stats_count);
	printf("[Number of files compressed: %9d]\n", stats_compresses);
	printf("[Number of files expanded:   %9d]\n", stats_expands);
	printf("\n");
}

///////////////////////////////////////////////////////////////////////////////

void printmode(const struct cramfs_inode *inode) {
	u16 mode = inode->mode;

	// Deal with file type bitsetc
	if (S_ISDIR(mode))
		printf("d");
	else if (S_ISLNK(mode))
		printf("l");
	else if (S_ISBLK(mode))
		printf("b");
	else if (S_ISCHR(mode))
		printf("c");
	else if (S_ISFIFO(mode))
		printf("p");
	else if (S_ISSOCK(mode))
		printf("s");
	else
		printf("-");

	// Deal with mode bits
	if (mode & S_IRUSR)
		printf("r");
	else
		printf("-");
	if (mode & S_IWUSR)
		printf("w");
	else
		printf("-");
	if (mode & S_IXUSR)
		if (mode & S_ISUID)
			printf("s");
		else
			printf("x");
	else if (mode & S_ISUID)
		printf("S");
	else
		printf("-");
	if (mode & S_IRGRP)
		printf("r");
	else
		printf("-");
	if (mode & S_IWGRP)
		printf("w");
	else
		printf("-");
	if (mode & S_IXGRP)
		if (mode & S_ISGID)
			printf("s");
		else
			printf("x");
	else if (mode & S_ISGID)
		printf("S");
	else
		printf("-");
	if (mode & S_IROTH)
		printf("r");
	else
		printf("-");
	if (mode & S_IWOTH)
		printf("w");
	else
		printf("-");
	if (mode & S_IXOTH)
		if (mode & S_ISVTX)
			printf("t");
		else
			printf("x");
	else if (mode & S_ISVTX)
		printf("T");
	else
		printf("-");
}

void printuidgid(const struct cramfs_inode *inode) {
	char res[14];

	snprintf(res, 14, "%d/%d", inode->uid, inode->gid);
	printf(" %-14s", res);

}

void printsize(int size, int csize) {
	char s[17];

	// As a side effect update the size stats
	updatestats(size, csize);

	snprintf(s, 17, "%7d(%d)", size, csize);
	printf("%-16s ", s);
}

///////////////////////////////////////////////////////////////////////////////

void do_file(const u8 * base, u32 offset, u32 size, const char *path, const char *name, int mode) {
	int fd;
	u8 *file_data;
	const u8 *srcdata;

	// Allow for uncompressed XIP executable
	if (mode & S_ISVTX) {
		// It seems that the offset may not necessarily be page
		// aligned. This is silly because mkcramfs wastes
		// the alignment space, whereas it might be used if it wasn't
		// bogusly in our file extent.
		//
		// blksize must be a power of 2 for the following to work, but it seems
		// quite likely.

		srcdata = (const u8 *)(((long)(base + offset) + blksize - 1) & ~(blksize - 1));

		//printsize(size, srcdata + size - (base + offset));
		//printf("%s", name);
	} else {
		//printsize(size, compressed_size(base, base + offset, size));
		//printf("%s", name);
	}

	// Check if we are actually unpacking
	if (path[0] == '-') {
		return;
	}
	// Make local copy
	fd = open(path, O_CREAT | O_TRUNC | O_RDWR, mode);
	if (fd == -1) {
		perror("create");
		return;
	};

	if (ftruncate(fd, size) == -1) {
		perror("ftruncate");
		close(fd);
		return;
	}

	file_data = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (file_data == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return;
	}
	// Allow for uncompressed XIP executable
	if (mode & S_ISVTX) {
		memcpy(file_data, srcdata, size);
	} else {
		uncompress_data(base, base + offset, size, file_data);
	}

	munmap(file_data, size);
	close(fd);

}

void do_directory(const u8 * base, u32 offset, u32 size, const char *path, const char *name, int mode) {
	//printsize(size, size);
	//printf("%s", name);

	// Check if we are actually unpacking
	if (path[0] == '-') {
		return;
	}
	// Make the local directory
	if (mkdir(path, mode) == -1) {
		perror(path);
		return;
	}
}

void do_symlink(const u8 * base, u32 offset, u32 size, const char *path, const char *name, int mode) {
	// Allocate the uncompressed string
	u8 link_contents[size + 1];

	// do uncompression
	uncompress_data(base, base + offset, size, link_contents);
	link_contents[size] = 0;

	printsize(size, compressed_size(base, base + offset, size));
	printf("%s -> %s", name, link_contents);

	// Check if we are actually unpacking
	if (path[0] == '-') {
		return;
	}
	// Make local copy
	if (symlink((const char *)link_contents, path) == -1) {
		perror(path);
		exit(1);
	}
}

void do_chrdev(const u8 * base, u32 offset, u32 size, const char *path, const char *name, int mode, int uid, int gid) {
	{
		char s[17];
		snprintf(s, 17, "%3d, %3d", major(size), minor(size));
		printf("%-16s %s", s, name);
	}

	// Check if we are actually unpacking
	if (path[0] == '-') {
		return;
	}
	// Make local copy
	if (geteuid() == 0) {
		if (mknod(path, S_IFCHR | mode, size) == -1)
			perror(path);
	} else if (opt_devfile) {
		char dfp[1024];
		char *p;
		FILE *f;

		strcpy(dfp, path);
		p = strrchr(dfp, '/');
		if (!p) {
			fprintf(stderr, "Could not find path in '%s'\n", path);
			return;
		}
		strcpy(p + 1, opt_devfile);
		f = fopen(dfp, "at");
		if (!f) {
			perror(dfp);
			return;
		}
		fprintf(f, "%s,%08x,%u,%u,%08x\n", name, mode, uid, gid, size);
		fclose(f);
	}
}

void do_blkdev(const u8 * base, u32 offset, u32 size, const char *path, const char *name, int mode, int uid, int gid) {
	{
		char s[17];
		snprintf(s, 17, "%3d, %3d", major(size), minor(size));
		//printf("%-16s %s", s, name);
	}

	// Check if we are actually unpacking
	if (path[0] == '-') {
		return;
	}
	// Make local copy
	if (geteuid() == 0) {
		if (mknod(path, S_IFBLK | mode, size) == -1)
			perror(path);
	} else if (opt_devfile) {
		char dfp[1024];
		char *p;
		FILE *f;

		strcpy(dfp, path);
		p = strrchr(dfp, '/');
		if (!p) {
			fprintf(stderr, "Could not find path in '%s'\n", path);
			return;
		}
		strcpy(p + 1, opt_devfile);
		f = fopen(dfp, "at");
		if (!f) {
			perror(dfp);
			return;
		}
		fprintf(f, "%s,%08x,%u,%u,%08x\n", name, mode, uid, gid, size);
		fclose(f);
	}
}

void do_fifo(const u8 * base, u32 offset, u32 size, const char *path, const char *name, int mode, int gid, int uid) {
	printf("                 %s", name);

	// Check if we are actually unpacking
	if (path[0] == '-') {
		return;
	}
	// Make local copy
	if (geteuid() == 0) {
		if (mknod(path, S_IFIFO | mode, 0) == -1)
			perror(path);
	} else if (opt_devfile) {
		char dfp[1024];
		char *p;
		FILE *f;

		strcpy(dfp, path);
		p = strrchr(dfp, '/');
		if (!p) {
			fprintf(stderr, "Could not find path in '%s'\n", path);
			return;
		}
		strcpy(p + 1, opt_devfile);
		f = fopen(dfp, "at");
		if (!f) {
			perror(dfp);
			return;
		}
		fprintf(f, "%s,%08x,%u,%u,%08x\n", name, mode, uid, gid, size);
		fclose(f);
	}
}

void do_socket(const u8 * base, u32 offset, u32 size, const char *path, const char *name, int mode) {
	printf("<UNIMPLEMENTED>  %s", name);

	// Check if we are actually unpacking
	if (path[0] == '-') {
		return;
	}
}

void do_unknown(const u8 * base, u32 offset, u32 size, const char *path, const char *name, int mode) {
	printf("<UNKNOWN TYPE>   %s", name);
}

void process_directory(const u8 * base, const char *dir, u32 offset, u32 size, const char *path) {
	struct cramfs_inode *de;
	char *name;
	int namelen;
	u32 current = offset;
	u32 dirend = offset + size;

	// Do files
	while (current < dirend) {
		u32 nextoffset;

		de = (struct cramfs_inode *)(base + current);
		namelen = de->namelen << 2;
		nextoffset = current + sizeof(struct cramfs_inode) + namelen;

		name = (char *)(de + 1);

		while (1) {
			assert(namelen != 0);

			if (name[namelen - 1])
				break;
			namelen--;
		}

		do_file_entry(base, dir, path, name, namelen, de);

		current = nextoffset;
	}

	// Recurse into directories
	current = offset;
	while (current < dirend) {
		u32 nextoffset;

		de = (struct cramfs_inode *)(base + current);
		namelen = de->namelen << 2;
		nextoffset = current + sizeof(struct cramfs_inode) + namelen;

		name = (char *)(de + 1);

		while (1) {
			assert(namelen != 0);

			if (name[namelen - 1])
				break;
			namelen--;
		}

		do_dir_entry(base, dir, path, name, namelen, de);

		current = nextoffset;
	}
}

///////////////////////////////////////////////////////////////////////////////

void do_file_entry(const u8 * base, const char *dir, const char *path, const char *name, int namelen, const struct cramfs_inode *inode) {
	int dirlen = strlen(dir);
	int pathlen = strlen(path);
	char pname[dirlen + pathlen + namelen + 3];
	const char *basename;
	u32 gid = inode->gid;

	if (dirlen) {
		strncpy(pname, dir, dirlen);
	}

	if (pathlen) {
		if (dirlen) {
			pname[dirlen] = '/';
			++dirlen;
		}
		strncpy(pname + dirlen, path, pathlen);
	}

	if (namelen) {
		if (pathlen + dirlen) {
			pname[dirlen + pathlen] = '/';
			++pathlen;
		}
		strncpy(pname + dirlen + pathlen, name, namelen);
	}

	pname[pathlen + dirlen + namelen] = 0;
	basename = namelen ? pname + dirlen + pathlen : "/";

	// Create things here
	//printmode(inode);
	//printuidgid(inode);

	if (S_ISREG(inode->mode)) {

		u32 size = inode->size;

		if (gid > DIR_GID) {
			// sirius: this is a special LG encoding of the size.
			// misusing gid field to encode the most significant byte of the size
			int lg = gid - DIR_GID;
			gid -= lg;
			lg = lg * 0x1000000;
			size += (lg);
		}

		do_file(base, inode->offset << 2, size, pname, basename, inode->mode);
	} else if (S_ISDIR(inode->mode)) {
		if (DIR_GID == 0) {
			DIR_GID = gid;
		}
		do_directory(base, inode->offset << 2, inode->size, pname, basename, inode->mode);
	} else if (S_ISLNK(inode->mode)) {
		do_symlink(base, inode->offset << 2, inode->size, pname, basename, inode->mode);
	} else if (S_ISFIFO(inode->mode)) {
		do_fifo(base, inode->offset << 2, inode->size, pname, basename, inode->mode, inode->uid, inode->gid);
	} else if (S_ISSOCK(inode->mode)) {
		do_socket(base, inode->offset << 2, inode->size, pname, basename, inode->mode);
	} else if (S_ISCHR(inode->mode)) {
		do_chrdev(base, inode->offset << 2, inode->size, pname, basename, inode->mode, inode->uid, inode->gid);
	} else if (S_ISBLK(inode->mode)) {
		do_blkdev(base, inode->offset << 2, inode->size, pname, basename, inode->mode, inode->uid, inode->gid);
	} else {
		do_unknown(base, inode->offset << 2, inode->size, pname, basename, inode->mode);
	}

	if (geteuid() == 0) {
		if (lchown(pname, inode->uid, gid) == -1)
			perror("cannot change owner or group");
	} else if (opt_idsfile && path && path[0]) {
		char dfp[1024];
		char *p;
		FILE *f;

		strcpy(dfp, pname);
		p = strrchr(dfp, '/');
		if (!p) {
			fprintf(stderr, "could not find path in '%s'\n", pname);
			return;
		}
		strcpy(p + 1, opt_idsfile);
		f = fopen(dfp, "at");
		if (!f) {
			perror(dfp);
			return;
		}
		fprintf(f, "%s,%u,%u,%08x\n", basename, inode->uid, inode->gid, inode->mode);
		fclose(f);
	}

	if (geteuid() == 0 || !opt_idsfile) {
		if (inode->mode & (S_ISGID | S_ISUID | S_ISVTX)) {
			if (0 != chmod(pname, inode->mode)) {
				perror("chmod");
				return;
			}
		}
	}
	//printf("\n");
}

void do_dir_entry(const u8 * base, const char *dir, const char *path, const char *name, int namelen, const struct cramfs_inode *inode) {
	int pathlen = strlen(path);
	char pname[pathlen + namelen + 2];

	if (pathlen) {
		strncpy(pname, path, pathlen);
	}

	if (namelen) {
		if (pathlen) {
			pname[pathlen] = '/';
			++pathlen;
		}
		strncpy(pname + pathlen, name, namelen);
	}

	pname[pathlen + namelen] = 0;

	// Only process directories here
	if (S_ISDIR(inode->mode)) {
		//printf("\n/%s:\n", pname);
		process_directory(base, dir, inode->offset << 2, inode->size, pname);
	}
}

///////////////////////////////////////////////////////////////////////////////
int is_cramfs_image(char const *imagefile, char *endian) {
	struct stat st;
	int fd, result;
	size_t fslen_ub;
	int *rom_image;
	struct cramfs_super const *sb;

	// Check the image file
	if (stat(imagefile, &st) == -1) {
		perror(imagefile);
		exit(1);
	}

	if (st.st_size < sizeof(struct cramfs_super)) {
		return 0;
	}

	// Map the cramfs image
	fd = open(imagefile, O_RDONLY);
	fslen_ub = st.st_size;
	rom_image = mmap(0, fslen_ub, PROT_READ, MAP_SHARED, fd, 0);
	if (rom_image == MAP_FAILED) {
		perror("Mapping cramfs file");
		exit(1);
	}

	sb = (struct cramfs_super const *)(rom_image);
	int cram_magic = CRAMFS_MAGIC;
	if (!memcmp(endian, "be", 2))
		SWAP(cram_magic);
	result = 0;
	// Check cramfs magic number and signature
	if (cram_magic == sb->magic || (memcmp(endian, "be", 2) && 0 == memcmp(sb->signature, CRAMFS_SIGNATURE, sizeof(sb->signature))))
		result = 1;

	munmap(rom_image, fslen_ub);
	close(fd);

	return result;
}

int uncramfs(char const *dirname, char const *imagefile) {

	struct stat st;
	int fd;
	size_t fslen_ub;
	u8 const *rom_image;
	struct cramfs_super const *sb;

	// Check the directory
	if (access(dirname, W_OK) == -1) {
		if (errno != ENOENT) {
			perror(dirname);
			exit(1);
		}
	}
	// Check the image file
	if (stat(imagefile, &st) == -1) {
		perror(imagefile);
		exit(1);
	}
	// Map the cramfs image
	fd = open(imagefile, O_RDONLY);
	fslen_ub = st.st_size;
	rom_image = mmap(0, fslen_ub, PROT_READ, MAP_SHARED, fd, 0);
	if (rom_image == MAP_FAILED) {
		perror("Mapping cramfs file");
		exit(1);
	}

	sb = (struct cramfs_super const *)(rom_image);
	// Check cramfs magic number and signature
	if (CRAMFS_MAGIC != sb->magic || 0 != memcmp(sb->signature, CRAMFS_SIGNATURE, sizeof(sb->signature))) {
		fprintf(stderr, "The image file doesn't have cramfs signatures\n");
		exit(1);
	}
	// Set umask to 0 to let the image modes shine through
	umask(0);

	clearstats();

	// Start doing...
	do_file_entry(rom_image, dirname, "", "", 0, &sb->root);
	do_dir_entry(rom_image, dirname, "", "", 0, &sb->root);

	return 0;
}
