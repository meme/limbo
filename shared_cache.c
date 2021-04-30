/*
 * Copyright © 2021 Keegan Saunders
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "shared_cache.h"

void *shared_cache_start = NULL;

static void rebase_chain(uint8_t *page_content, uint16_t page_start_offset,
		dyld_cache_slide_info2_t *info);
static void rebase_page(dyld_cache_slide_info2_t *info, uint64_t address);

void
shared_cache_mmap(char *data, int f)
{
	dyld_cache_slide_info2_t *info;
	dyld_cache_header_t *header;
	dyld_cache_mapping_and_slide_info_t *slides;

	header = (dyld_cache_header_t *)data;
	slides = (dyld_cache_mapping_and_slide_info_t *)(data
			+ header->mappingWithSlideOffset);

	for (uint32_t i = 0; i < header->mappingWithSlideCount; i++) {
		dyld_cache_mapping_and_slide_info_t slide = slides[i];

		/* Let all the mappings leak, they will never be removed */
		void *base = mmap((void *)slide.address, slide.size,
				slide.initProt, MAP_PRIVATE | MAP_FIXED, f,
				slide.fileOffset);
		if (base == MAP_FAILED) {
			perror("mmap");
			return;
		}

		info = (dyld_cache_slide_info2_t *)(data
				+ slide.slideInfoFileOffset);

		if (slide.slideInfoFileOffset) {
			assert(info->version == 2);
			assert(info->page_size == 0x1000);
			assert(info->delta_mask == 0x00ffff0000000000);
			assert(info->page_starts_count
					== slide.size / info->page_size);
			rebase_page(info, slide.address);
		}
	}

	shared_cache_start = (void *)header->sharedRegionStart;
}

/*
 * For details on how sliding the dyld cache works, see dyld_cache_slide_info2
 * in dyld_cache_format.h
 */
static void
rebase_page(dyld_cache_slide_info2_t *info, uint64_t address)
{
	uint16_t *page_starts = (uint16_t *)((uintptr_t)info
			+ info->page_starts_offset);
	uint16_t *page_extras = (uint16_t *)((uintptr_t)info
			+ info->page_extras_offset);

	for (uint32_t j = 0; j < info->page_starts_count; j++) {
		uint8_t *page_content
				= (uint8_t *)(address + j * info->page_size);
		uint16_t page_entry = page_starts[j];
		uint16_t page_start_offset = page_entry << 2;

		if (page_entry == DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE) {
			continue;
		}

		if (page_entry & DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA) {
			/* Multiple linked-lists are needed to rebase */
			uint16_t chain_index = page_entry & 0x3fff;
			uint16_t extra;

			/* High-level algorithm described in dyld_cache_format.h
			 */
			do {
				uint16_t page_start_offset;

				assert(chain_index < info->page_extras_count);

				extra = page_extras[chain_index];
				page_start_offset = (uint16_t)(
						(extra & 0x3fff) << 2);

				rebase_chain(page_content, page_start_offset,
						info);

				chain_index++;
			} while (!(extra & DYLD_CACHE_SLIDE_PAGE_ATTR_END));
		} else {
			/* Standalone linked-list provides rebase details */
			rebase_chain(page_content, page_start_offset, info);
		}
	}
}

static void
rebase_chain(uint8_t *page_content, uint16_t page_offset,
		dyld_cache_slide_info2_t *info)
{
	uint32_t last_page_offset = info->page_size - sizeof(uint64_t);

	uint64_t delta_mask = info->delta_mask;
	uint64_t value_mask = ~delta_mask;
	uint64_t value_add = info->value_add;
	uint64_t delta_shift = __builtin_ctzll(delta_mask) - 2;

	uint32_t delta;
	for (delta = 1; delta != 0 && page_offset <= last_page_offset;
			page_offset += delta) {
		uint8_t *l = page_content + page_offset;

		uint64_t value;
		memcpy(&value, l, sizeof(value));

		delta = (uint32_t)((value & delta_mask) >> delta_shift);
		value &= value_mask;

		if (value != 0) {
			value += value_add;
			/* No need to add slide, we don't rebase it */
		}

		memcpy(l, &value, sizeof(value));
	}
}
