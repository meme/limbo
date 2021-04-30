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

#include <mach/mach.h>

#define HOST_REPLY_PORT           ((mach_port_t)0xcafebabe)
#define TASK_REPLY_PORT           ((mach_port_t)0xbabebabe)
#define THREAD_REPLY_PORT         ((mach_port_t)0xcafe0001)
#define MACH_REPLY_PORT           ((mach_port_t)0xdeadbeef)
#define SYSTEM_CLOCK_PORT         ((mach_port_t)0xbabe0002)
#define BOOTSTRAP_PORT            ((mach_port_t)0x000babe0)
#define HOST_SPECIAL_PORT_1       ((mach_port_t)0x000babe1)
#define THREAD_SPECIAL_REPLY_PORT ((mach_port_t)0x000babe2)

/* Not defined in the headers, for some reason */

typedef struct {
	mach_vm_address_t location;
	unsigned short length;
	unsigned short recovery_offs;
	unsigned int flags;
} task_restartable_range_t;

typedef task_restartable_range_t *task_restartable_range_array_t;

boolean_t mach_host_server(
		mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);
boolean_t task_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);
boolean_t bootstrap_server(
		mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);
