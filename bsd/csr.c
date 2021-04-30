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
#include "xnu-errno.h"

#define CSR_ALLOW_UNTRUSTED_KEXTS            (1 << 0)
#define CSR_ALLOW_UNRESTRICTED_FS            (1 << 1)
#define CSR_ALLOW_TASK_FOR_PID               (1 << 2)
#define CSR_ALLOW_KERNEL_DEBUGGER            (1 << 3)
#define CSR_ALLOW_APPLE_INTERNAL             (1 << 4)
#define CSR_ALLOW_DESTRUCTIVE_DTRACE         (1 << 5)
#define CSR_ALLOW_UNRESTRICTED_DTRACE        (1 << 5)
#define CSR_ALLOW_UNRESTRICTED_NVRAM         (1 << 6)
#define CSR_ALLOW_DEVICE_CONFIGURATION       (1 << 7)
#define CSR_ALLOW_ANY_RECOVERY_OS            (1 << 8)
#define CSR_ALLOW_UNAPPROVED_KEXTS           (1 << 9)
#define CSR_ALLOW_EXECUTABLE_POLICY_OVERRIDE (1 << 10)
#define CSR_ALLOW_UNAUTHENTICATED_ROOT       (1 << 11)

enum csr_syscalls {
	CSR_SYSCALL_CHECK,
	CSR_SYSCALL_GET_ACTIVE_CONFIG,
};

static int
csr_check(void *useraddr, void *usersize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "csr_check(%p, %p)\n", useraddr, usersize);
#endif
	uint32_t mask = 0;
	if ((uint64_t)usersize != 4) {
		return err_map(EFAULT);
	}

	mask = *(uint32_t *)useraddr;

	switch (mask) {
	case CSR_ALLOW_TASK_FOR_PID:
		return 0;
	/* As far as I can tell, if this is TRUE then it indicates SIP */
	case CSR_ALLOW_APPLE_INTERNAL:
		return 1;
	case CSR_ALLOW_UNRESTRICTED_FS:
		return 1;
	default:
		unimplemented();
	}
}

int
sys_csrctl(uint32_t op, user_addr_t useraddr, user_addr_t usersize)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "csrctl(%p, %p, %p)\n", (void *)op, (void *)useraddr,
			(void *)usersize);
#endif
	switch (op) {
	case CSR_SYSCALL_CHECK:
		return csr_check(useraddr, usersize);
	default:
		unimplemented();
	}
}
