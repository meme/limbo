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

#include <stdio.h>

#include "handler.h"

#define MAC_MAX_POLICY_NAME 32

#define AMFI_DYLD_OUTPUT_ALLOW_AT_PATH                  (1 << 0)
#define AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS                (1 << 1)
#define AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE      (1 << 2)
#define AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS           (1 << 3)
#define AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS               (1 << 4)
#define AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION (1 << 5)
#define AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING      (1 << 6)

static int
amfi_handle_check_dyld_policy_self_syscall(long arg)
{
	long data[2];

	memcpy(data, (void *)arg, sizeof(data));

	long res = AMFI_DYLD_OUTPUT_ALLOW_AT_PATH
			| AMFI_DYLD_OUTPUT_ALLOW_PATH_VARS
			| AMFI_DYLD_OUTPUT_ALLOW_CUSTOM_SHARED_CACHE
			| AMFI_DYLD_OUTPUT_ALLOW_FALLBACK_PATHS
			| AMFI_DYLD_OUTPUT_ALLOW_PRINT_VARS
			| AMFI_DYLD_OUTPUT_ALLOW_FAILED_LIBRARY_INSERTION
			| AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING;

	memcpy((void *)data[1], &res, sizeof(res));

	return 0;
}

static int
amfi_handle_syscall(int call, void *arg)
{
	switch (call) {
	case 90:
		return amfi_handle_check_dyld_policy_self_syscall((long)arg);
	default:
		unimplemented();
	}
}

int
sys___mac_syscall(char *policy, int call, user_addr_t arg)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "__mac_syscall(%p, %p, %p)\n", (void *)policy,
			(void *)call, (void *)arg);
#endif
	if (strncmp(policy, "AMFI", MAC_MAX_POLICY_NAME) == 0) {
		return amfi_handle_syscall(call, arg);
	} else if (strncmp(policy, "Sandbox", MAC_MAX_POLICY_NAME) == 0) {
		return 1;
	} else {
		unimplemented();
	}
}
