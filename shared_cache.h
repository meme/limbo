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

#pragma once

#define DYLD_CACHE_SLIDE_PAGE_ATTR_END       0x8000
#define DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA     0x8000
#define DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE 0x4000

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
	uint64_t patchInfoAddr;
	uint64_t patchInfoSize;
	uint64_t otherImageGroupAddrUnused;
	uint64_t otherImageGroupSizeUnused;
	uint64_t progClosuresAddr;
	uint64_t progClosuresSize;
	uint64_t progClosuresTrieAddr;
	uint64_t progClosuresTrieSize;
	uint32_t platform;
	uint32_t formatVersion : 8, dylibsExpectedOnDisk : 1, simulator : 1,
			locallyBuiltCache : 1, builtFromChainedFixups : 1,
			padding : 20;
	uint64_t sharedRegionStart;
	uint64_t sharedRegionSize;
	uint64_t maxSlide;
	uint64_t dylibsImageArrayAddr;
	uint64_t dylibsImageArraySize;
	uint64_t dylibsTrieAddr;
	uint64_t dylibsTrieSize;
	uint64_t otherImageArrayAddr;
	uint64_t otherImageArraySize;
	uint64_t otherTrieAddr;
	uint64_t otherTrieSize;
	uint32_t mappingWithSlideOffset;
	uint32_t mappingWithSlideCount;
} dyld_cache_header_t;

typedef struct {
	uint64_t address;
	uint64_t size;
	uint64_t fileOffset;
	uint64_t slideInfoFileOffset;
	uint64_t slideInfoFileSize;
	uint64_t flags;
	uint32_t maxProt;
	uint32_t initProt;
} dyld_cache_mapping_and_slide_info_t;

typedef struct {
	uint32_t version;
	uint32_t page_size;
	uint32_t page_starts_offset;
	uint32_t page_starts_count;
	uint32_t page_extras_offset;
	uint32_t page_extras_count;
	uint64_t delta_mask;
	uint64_t value_add;
} dyld_cache_slide_info2_t;

extern void *shared_cache_start;

void shared_cache_mmap(char *data, int f);
