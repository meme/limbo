/*
 * Copyright © 2021 Keegan Saunders
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <fcntl.h>
#include <mach-o/loader.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
	char magic[16];
	uint32_t mappingOffset;
	uint32_t mappingCount;
	uint32_t imagesOffset;
	uint32_t imagesCount;
	uint64_t dyldBaseAddress;
	uint64_t codeSignatureOffset;
	uint64_t codeSignatureSize;
	uint64_t slideInfoOffsetUnused;
	uint64_t slideInfoSizeUnused;
	uint64_t localSymbolsOffset;
	uint64_t localSymbolsSize;
	uint8_t uuid[16];
	uint64_t cacheType;
	uint32_t branchPoolsOffset;
	uint32_t branchPoolsCount;
	uint64_t accelerateInfoAddr;
	uint64_t accelerateInfoSize;
	uint64_t imagesTextOffset;
	uint64_t imagesTextCount;
} dyld_cache_header_t;

typedef struct {
	uint64_t address;
	uint64_t modTime;
	uint64_t inode;
	uint32_t pathFileOffset;
	uint32_t pad;
} dyld_cache_image_info_t;

typedef struct {
	uint64_t address;
	uint64_t size;
	uint64_t fileOffset;
	uint32_t maxProt;
	uint32_t initProt;
} dyld_cache_mapping_info_t;

int
main(int argc, char *argv[])
{
	if (argc < 3) {
		fprintf(stderr, "Usage: cache-lookup [address] [path]\n");
		return 1;
	}

	char *end;
	uint64_t n = strtoull(argv[1], &end, 16);
	if (argv[1] == end) {
		fprintf(stderr, "cache-lookup: invalid address\n");
		return 1;
	}

	int fd = open(argv[2], O_RDONLY);
	if (fd == -1) {
		perror("cache-lookup: open");
		return 1;
	}

	struct stat s = {0};
	if (fstat(fd, &s) == -1) {
		perror("cache-lookup: fstat");
		close(fd);
		return 1;
	}

	size_t data_size = s.st_size;
	uint8_t *data = mmap(NULL, data_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == MAP_FAILED) {
		perror("cache-lookup: mmap");
		close(fd);
		return 1;
	}

	dyld_cache_header_t *header = (dyld_cache_header_t *)data;
	dyld_cache_mapping_info_t *mappings = (dyld_cache_mapping_info_t *)(data
			+ header->mappingOffset);
	dyld_cache_image_info_t *images = (dyld_cache_image_info_t *)(data
			+ header->imagesOffset);

	for (uint32_t i = 0; i < header->imagesCount; i++) {
		const char *path = (char *)data + images[i].pathFileOffset;
		uintptr_t address = images[i].address;
		for (uint32_t j = 0; j < header->mappingCount; j++) {
			if (address >= mappings[j].address
					&& address <= mappings[j].address
									+ mappings[j].size) {
				address -= mappings[j].address;
			}
		}
		struct mach_header_64 *header
				= (struct mach_header_64 *)(data + address);

		uintptr_t __TEXT_start = 0;
		uintptr_t __TEXT_end = 0;
		uint8_t *lc_start = NULL;
		uint8_t *lc_end = NULL;
		struct load_command *command
				= (struct load_command *)(header + 1);
		for (uint32_t i = 0; i < header->ncmds; i++) {
			switch (command->cmd) {
			case LC_SEGMENT_64: {
				struct segment_command_64 *cmd
						= (struct segment_command_64 *)
								command;
				if (cmd->initprot & VM_PROT_EXECUTE) {
					__TEXT_start = cmd->vmaddr;
					__TEXT_end = __TEXT_start + cmd->vmsize;
				}
			} break;
			case LC_FUNCTION_STARTS: {
				struct linkedit_data_command *cmd = (struct
						linkedit_data_command *)command;
				lc_start = (uint8_t *)data + cmd->dataoff;
				lc_end = lc_start + cmd->datasize;
			} break;
			}

			command = (struct load_command *)((char *)command
					+ command->cmdsize);
		}

		if (n >= __TEXT_start && n <= __TEXT_end) {
			if (lc_start != NULL) {
				/* The first address that is greater than our
				 * target is the function after the containing
				 * function */
				uintptr_t estart = 0;
				uintptr_t address = __TEXT_start;
				/* ld64/dyldinfo.cpp */
				for (uint8_t *p = lc_start;
						(*p != 0) && (p < lc_end);) {
					uint64_t delta = 0;
					uint32_t shift = 0;
					int more = 1;
					do {
						uint8_t byte = *p++;
						delta |= ((byte & 0x7F)
								<< shift);
						shift += 7;
						if (byte < 0x80) {
							address += delta;
							if (address >= n) {
								goto beach;
							}
							estart = address;
							more = 0;
						}
					} while (more);
				}
beach:
				printf("%s`%#lx+%#lx\n", path, estart,
						n - estart);
			} else {
				printf("%s\n", path);
			}
		}
	}

	munmap(data, data_size);
	return 0;
}
