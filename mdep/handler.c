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

#include <asm/prctl.h>
#include <stdio.h>
#include <stdlib.h>

#include "handler.h"

int arch_prctl(int code, unsigned long addr);

static int
sys_thread_set_tsd_base(uint64_t thread, uint64_t tsd_base)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_set_tsd_base(%p, %p)\n", (void *)thread,
			(void *)tsd_base);
#endif
	arch_prctl(ARCH_SET_GS, thread);
	return 0;
}

uint64_t
sys_mdep(unsigned long syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t *sp)
{
	switch (syscall) {
	case 0x3:
		return sys_thread_set_tsd_base(arg1, arg2);
	default:
#ifdef ENABLE_STRACE
		printf(">> Missing machine-dependent system call: %#lx\n",
				syscall);
#endif
		abort();
	}
}
