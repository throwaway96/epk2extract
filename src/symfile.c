/*
 * Copyright (c) 2011 Roman Tokarev <roman.s.tokarev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <symfile.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#define MAGIC 0xB12791EE

struct symfile_header {
	uint32_t magic;
	uint32_t unknown;
	uint32_t size;
	uint32_t n_symbols;
	uint32_t tail_size;
}__attribute__((packed));

struct sym_table sym_table = {
	.n_symbols = 0,
	.sym_entry = NULL,
	.hash = NULL,
	.n_dwarf_lst = 0,
	.dwarf_lst = NULL,
	.dwarf_data = NULL,
	.sym_name = NULL
};

int symfile_load(const char *fname) {
	int fd = open(fname, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "can't open `%s': %s\n", fname, strerror(errno));

		goto failed;
	}

	struct stat st_buf;
	if (fstat(fd, &st_buf) != 0) {
		fprintf(stderr, "fstat for `%s' is failed: %s\n", fname, strerror(errno));

		goto failed_close;
	}

	if (st_buf.st_size < sizeof(struct symfile_header)) {
		// silently ignore too-small files

		goto failed_close;
	}

	void *const map = mmap(NULL, st_buf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (map == NULL) {
		fprintf(stderr, "can't mmap `%s': %s\n", fname, strerror(errno));

		goto failed_close;
	}

	void *p = map;
	const struct symfile_header *const header = p;
	p += sizeof(*header);
	if (header->magic != MAGIC) {
		// silently ignore files with bad magic

		goto failed_unmap;
	}

	const uint_least32_t expected_size = header->size + sizeof(*header);
	if (expected_size != (uint_least32_t) st_buf.st_size) {
		fprintf(stderr, "bad file `%s' (size): %ju, expected size: %" PRIuLEAST32 "\n",
			fname, (uintmax_t) st_buf.st_size, expected_size);

		goto failed_unmap;
	}

	const uint32_t calc_size = header->tail_size + sizeof(struct sym_entry) * header->n_symbols;
	if (calc_size != header->size) {
		fprintf(stderr, "bad file `%s': inconsistent sizes in header (%" PRIu32 " != %" PRIu32 ")\n",
			fname, calc_size, header->size);

		goto failed_unmap;
	}

	sym_table.n_symbols = header->n_symbols;
	sym_table.sym_entry = p;
	p += sizeof(sym_table.sym_entry[0]) * sym_table.n_symbols;

	const uint32_t *const has_hash = p;
	p += sizeof(*has_hash);
	if ((*has_hash != 2) && (*has_hash != 0)) {
		fprintf(stderr, "unsupported file `%s' format: unexpected has_hash 0x%x\n",
			fname, *has_hash);

		goto failed_unmap;
	}

	if (*has_hash == 2) {
		sym_table.hash = p;
		// round up to even number of symbols
		const uint32_t rounded_count = (sym_table.n_symbols + 1) & (~((uint32_t) 1));
		p += sizeof(sym_table.hash[0]) * rounded_count;
	}

	const uint32_t *const has_dwarf = p;
	p += sizeof(*has_dwarf);

	if (*has_dwarf == 1) {
		sym_table.n_dwarf_lst = *(uint32_t *) p;
		p += sizeof(sym_table.n_dwarf_lst);
		const uint32_t dwarf_data_size = *(uint32_t *) p;
		p += sizeof(dwarf_data_size);
		sym_table.dwarf_lst = p;
		p += sizeof(sym_table.dwarf_lst[0]) * sym_table.n_dwarf_lst;
		sym_table.dwarf_data = p;
		p += dwarf_data_size;
		sym_table.sym_name = p;
	} else {
		sym_table.sym_name = (const char *) has_dwarf;
	}

	printf("`%s' has been successfully loaded\n", fname);

	return 0;

failed_unmap:
	if (munmap(map, st_buf.st_size) != 0) {
		fprintf(stderr, "can't unmap `%s' (error %d): %s\n", fname, errno, strerror(errno));
	}

failed_close:
	if (close(fd) != 0) {
		fprintf(stderr, "can't close `%s' (error %d): %s\n", fname, errno, strerror(errno));
	}

failed:
	return -1;
}

uint32_t symfile_addr_by_name(const char *name) {
	for (unsigned int i = 0; i < sym_table.n_symbols; ++i) {
		const char *sym_name = sym_table.sym_name + sym_table.sym_entry[i].sym_name_off;

		if (strcmp(sym_name, name) == 0) {
			return sym_table.sym_entry[i].addr;
		}
	}

	return 0;
}

uint32_t symfile_n_symbols() {
	return sym_table.n_symbols;
}

void symfile_write_idc(const char *fname) {
	FILE *outfile = fopen(fname, "w");
	if (outfile == NULL) {
		fprintf(stderr, "can't open `%s' for writing: %s\n", fname, strerror(errno));
		return;
	}

	fprintf(outfile, "#include <idc.idc>\n\n");
	fprintf(outfile, "static main() {\n");

	for (unsigned int i = 0; i < sym_table.n_symbols; ++i) {
			const char *sym_name = sym_table.sym_name
					+ sym_table.sym_entry[i].sym_name_off;

			uint32_t addr = sym_table.sym_entry[i].addr;
			uint32_t end = sym_table.sym_entry[i].end;

			fprintf(outfile, "\tMakeNameEx(0x%x, \"%s\", SN_NOWARN | SN_CHECK);\n", addr, sym_name);

			fprintf(outfile, "\tif (SegName(0x%x)==\".text\") {\n", addr);
			fprintf(outfile, "\t\tMakeCode(0x%x);\n", addr);
			fprintf(outfile, "\t\tMakeFunction(0x%x, 0x%x);\n", addr, end);
			fprintf(outfile, "\t};\n");
	}

	fprintf(outfile, "}\n");

	if (fclose(outfile) != 0) {
		fprintf(stderr, "can't close `%s' (error %d): %s\n", fname, errno, strerror(errno));
	}
}

const char *symfile_name_by_addr(uint32_t addr) {
	for (int i = sym_table.n_symbols - 1; i >= 0; --i) {
		if (sym_table.sym_entry[i].addr <= addr && sym_table.sym_entry[i].end > addr) {
			return sym_table.sym_name + sym_table.sym_entry[i].sym_name_off;
		}
	}

	return NULL;
}
