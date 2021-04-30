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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <asm/prctl.h>
#include <assert.h>
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/i386/thread_status.h>
#include <mach/mach.h>
#include <mach/machine/ndr_def.h> /* NDR_Record */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <ucontext.h>
#include <unistd.h>

#include "bootstrap/bootstrap.h" /*__ReplyUnion__bootstrap_subsystem */
#include "handler.h"
#include "port.h"

int
sys_kern_invalid(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kern_invalid()\n");
#endif
	unimplemented();
}

mach_port_name_t
sys_mach_reply_port(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_reply_port()\n");
#endif
	return MACH_REPLY_PORT;
}

mach_port_name_t
sys_thread_get_special_reply_port(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_get_special_reply_port()\n");
#endif
	return THREAD_SPECIAL_REPLY_PORT;
}

mach_port_name_t
sys_thread_self_trap(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_self_trap()\n");
#endif
	return THREAD_REPLY_PORT;
}

mach_port_name_t
sys_host_self_trap(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_self_trap()\n");
#endif
	return HOST_REPLY_PORT;
}

mach_msg_return_t
sys_mach_msg_trap(mach_msg_header_t *msg, mach_msg_option_t option,
		mach_msg_size_t send_size, mach_msg_size_t rcv_size,
		mach_port_t rcv_name, mach_msg_timeout_t timeout,
		mach_port_t notify)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_msg_trap(%p, %p, %p, %p, %p, %p, %p)\n",
			(void *)msg, (void *)option, (void *)send_size,
			(void *)rcv_size, (void *)rcv_name, (void *)timeout,
			(void *)notify);
#endif
	mach_msg_header_t *output;

	/* TODO: Read the disposition of the request and check if it is
	 * send/receive right now we just copy over all the messages. */

	/* TODO: There is a bug somewhere where the MIG generator sets a
	 * disposition of copy on messages, so you need to change the
	 * disposition in the MIG generated code from 19 to 17 (copy to move) */

#ifdef ENABLE_STRACE
	fprintf(stderr, ">> Mach message: port: %#x, message ID: %d\n",
			msg->msgh_remote_port, msg->msgh_id);
#endif

	switch (msg->msgh_remote_port) {
	case HOST_REPLY_PORT:
		output = malloc(sizeof(
				union __ReplyUnion__mach_host_subsystem));
		mach_host_server(msg, output);
		/* TODO: Not clear on why this is required, but type checking
		 * fails if the remote port is not NULL */
		output->msgh_remote_port = MACH_PORT_NULL;
		memcpy(msg, output, output->msgh_size);
		free(output);
		break;
	case TASK_REPLY_PORT:
		output = malloc(sizeof(union __ReplyUnion__task_subsystem));
		task_server(msg, output);
		/* TODO: Not clear on why this is required, but type checking
		 * fails if the remote port is not NULL */
		output->msgh_remote_port = MACH_PORT_NULL;
		memcpy(msg, output, output->msgh_size);
		free(output);
		break;
	case BOOTSTRAP_PORT:
		output = malloc(sizeof(
				union __ReplyUnion__bootstrap_subsystem));
		bootstrap_server(msg, output);
		memcpy(msg, output, output->msgh_size);
		free(output);
		break;
	default:
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> Unhandled remote port: %#x\n",
				msg->msgh_remote_port);
#endif
		// abort();
		return KERN_FAILURE;
	}

	return KERN_SUCCESS;
}

mach_msg_return_t
sys_mach_msg_overwrite_trap(mach_msg_header_t *msg, mach_msg_option_t option,
		mach_msg_size_t send_size, mach_msg_size_t rcv_size,
		mach_port_name_t rcv_name, mach_msg_timeout_t timeout,
		mach_msg_priority_t priority, mach_msg_header_t *rcv_msg,
		mach_msg_size_t rcv_limit)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_msg_overwrite_trap(%p, %p, %p, %p, %p, %p, %p, "
			"%p, %p)\n",
			(void *)msg, (void *)option, (void *)send_size,
			(void *)rcv_size, (void *)rcv_name, (void *)timeout,
			(void *)priority, (void *)rcv_msg, (void *)rcv_limit);
#endif
	unimplemented();
}

kern_return_t
sys_semaphore_signal_trap(mach_port_name_t signal_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_signal_trap(%p)\n", (void *)signal_name);
#endif
	unimplemented();
}

kern_return_t
sys_semaphore_signal_all_trap(mach_port_name_t signal_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_signal_all_trap(%p)\n", (void *)signal_name);
#endif
	unimplemented();
}

kern_return_t
sys_semaphore_signal_thread_trap(
		mach_port_name_t signal_name, mach_port_name_t thread_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_signal_thread_trap(%p, %p)\n",
			(void *)signal_name, (void *)thread_name);
#endif
	unimplemented();
}

kern_return_t
sys_semaphore_wait_trap(mach_port_name_t wait_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_wait_trap(%p)\n", (void *)wait_name);
#endif
	unimplemented();
}

kern_return_t
sys_semaphore_wait_signal_trap(
		mach_port_name_t wait_name, mach_port_name_t signal_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_wait_signal_trap(%p, %p)\n",
			(void *)wait_name, (void *)signal_name);
#endif
	unimplemented();
}

kern_return_t
sys_semaphore_timedwait_trap(
		mach_port_name_t wait_name, unsigned int sec, clock_res_t nsec)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_timedwait_trap(%p, %p, %p)\n",
			(void *)wait_name, (void *)sec, (void *)nsec);
#endif
	unimplemented();
}

kern_return_t
sys_semaphore_timedwait_signal_trap(mach_port_name_t wait_name,
		mach_port_name_t signal_name, unsigned int sec,
		clock_res_t nsec)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_timedwait_signal_trap(%p, %p, %p, %p)\n",
			(void *)wait_name, (void *)signal_name, (void *)sec,
			(void *)nsec);
#endif
	unimplemented();
}

kern_return_t
sys_clock_sleep_trap(mach_port_name_t clock_name, sleep_type_t sleep_type,
		int sleep_sec, int sleep_nsec, mach_timespec_t *wakeup_time)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "clock_sleep_trap(%p, %p, %p, %p, %p)\n",
			(void *)clock_name, (void *)sleep_type,
			(void *)sleep_sec, (void *)sleep_nsec,
			(void *)wakeup_time);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_vm_allocate_trap(mach_port_name_t target,
		mach_vm_offset_t *addr, mach_vm_size_t size, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_allocate_trap(%p, %p, %p, %p)\n",
			(void *)target, (void *)addr, (void *)size,
			(void *)flags);
#endif
	void *map = mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANON, -1, 0);
	if (map == MAP_FAILED) {
#ifdef ENABLE_STRACE
		perror("mmap");
#endif
		return KERN_INVALID_ADDRESS;
	} else {
		*(uint64_t *)addr = (uint64_t)map;
		return KERN_SUCCESS;
	}
}

kern_return_t
sys__kernelrpc_mach_vm_deallocate_trap(mach_port_name_t target,
		mach_vm_address_t address, mach_vm_size_t size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_deallocate_trap(%p, %p, %p)\n",
			(void *)target, (void *)address, (void *)size);
#endif
	/* TODO: Handle deallocating mappings */
	return KERN_SUCCESS;
}

kern_return_t
sys__kernelrpc_mach_vm_protect_trap(mach_port_name_t target,
		mach_vm_address_t address, mach_vm_size_t size,
		boolean_t set_maximum, vm_prot_t new_protection)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_protect_trap(%p, %p, %p, %p, %p)\n",
			(void *)target, (void *)address, (void *)size,
			(void *)set_maximum, (void *)new_protection);
#endif
	/* TODO: Convert protection and return code */
	return mprotect((void *)address, size, new_protection);
}

#define VM_FLAGS_FIXED              0x0000
#define VM_FLAGS_ANYWHERE           0x0001
#define VM_FLAGS_PURGABLE           0x0002
#define VM_FLAGS_4GB_CHUNK          0x0004
#define VM_FLAGS_RANDOM_ADDR        0x0008
#define VM_FLAGS_NO_CACHE           0x0010
#define VM_FLAGS_RESILIENT_CODESIGN 0x0020
#define VM_FLAGS_RESILIENT_MEDIA    0x0040
#define VM_FLAGS_OVERWRITE          0x4000

kern_return_t
sys__kernelrpc_mach_vm_map_trap(mach_port_name_t target,
		mach_vm_offset_t *address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, vm_prot_t cur_protection)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_vm_map_trap(%p, %p, %p, %p, %p, %p)\n",
			(void *)target, (void *)address, (void *)size,
			(void *)mask, (void *)flags, (void *)cur_protection);
#endif
	/* TODO: Convert flags and protection appropriately */
	void *base = NULL;
	/* HACK: Sleep with one eye open */
	size *= 4;
	/* Fixed mapping, anywhere is not set */
	if ((flags & VM_FLAGS_ANYWHERE) == 0) {
		base = mmap((void *)*address, size, cur_protection,
				MAP_PRIVATE | MAP_ANON | MAP_FIXED, -1, 0);
		/* Anywhere mapping*/
	} else {
		if (*address != PAGE_SIZE) {
			base = mmap((void *)*address, size, cur_protection,
					MAP_PRIVATE | MAP_ANON | MAP_FIXED
							| MAP_FIXED_NOREPLACE,
					-1, 0);
			while (base == MAP_FAILED) {
				*address += 0x400000;
				base = mmap((void *)*address, size,
						cur_protection,
						MAP_PRIVATE | MAP_ANON
								| MAP_FIXED
								| MAP_FIXED_NOREPLACE,
						-1, 0);
			}
		} else {
			base = mmap(NULL, size, cur_protection,
					MAP_PRIVATE | MAP_ANON, -1, 0);
		}

		*address = (mach_vm_offset_t)base;
	}

	if (base == MAP_FAILED) {
		perror("mmap");
		return -EINVAL;
	}
	return KERN_SUCCESS;
}

kern_return_t
sys__kernelrpc_mach_vm_purgable_control_trap(mach_port_name_t target,
		mach_vm_offset_t address, vm_purgable_t control, int *state)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_vm_purgable_control_trap(%p, %p, %p, "
			"%p)\n",
			(void *)target, (void *)address, (void *)control,
			(void *)state);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_allocate_trap(mach_port_name_t target,
		mach_port_right_t right, mach_port_name_t *name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_allocate_trap(%p, %p, %p)\n",
			(void *)target, (void *)right, (void *)name);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_deallocate_trap(
		mach_port_name_t target, mach_port_name_t name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_deallocate_trap(%p, %p)\n",
			(void *)target, (void *)name);
#endif
	/* TODO: Handle deallocating ports */
	return KERN_SUCCESS;
}

kern_return_t
sys__kernelrpc_mach_port_mod_refs_trap(mach_port_name_t target,
		mach_port_name_t name, mach_port_right_t right,
		mach_port_delta_t delta)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_mod_refs_trap(%p, %p, %p, %p)\n",
			(void *)target, (void *)name, (void *)right,
			(void *)delta);
#endif
	/* TODO: Handle */
	return KERN_FAILURE;
}

kern_return_t
sys__kernelrpc_mach_port_move_member_trap(mach_port_name_t target,
		mach_port_name_t member, mach_port_name_t after)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_move_member_trap(%p, %p, %p)\n",
			(void *)target, (void *)member, (void *)after);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_insert_right_trap(mach_port_name_t target,
		mach_port_name_t name, mach_port_name_t poly,
		mach_msg_type_name_t polyPoly)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_port_insert_right_trap(%p, %p, %p, "
			"%p)\n",
			(void *)target, (void *)name, (void *)poly,
			(void *)polyPoly);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_get_attributes_trap(mach_port_name_t target,
		mach_port_name_t name, mach_port_flavor_t flavor,
		mach_port_info_t port_info_out,
		mach_msg_type_number_t *port_info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_port_get_attributes_trap(%p, %p, %p, "
			"%p, %p)\n",
			(void *)target, (void *)name, (void *)flavor,
			(void *)port_info_out, (void *)port_info_outCnt);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_insert_member_trap(mach_port_name_t target,
		mach_port_name_t name, mach_port_name_t pset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_insert_member_trap(%p, %p, %p)\n",
			(void *)target, (void *)name, (void *)pset);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_extract_member_trap(mach_port_name_t target,
		mach_port_name_t name, mach_port_name_t pset)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_port_extract_member_trap(%p, %p, "
			"%p)\n",
			(void *)target, (void *)name, (void *)pset);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_construct_trap(mach_port_name_t target,
		mach_port_options_t *options, uint64_t context,
		mach_port_name_t *name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_construct_trap(%p, %p, %p, %p)\n",
			(void *)target, (void *)options, (void *)context,
			(void *)name);
#endif
	/* TODO: Handle */
	/* return KERN_FAILURE; */
	return KERN_SUCCESS;
}

kern_return_t
sys__kernelrpc_mach_port_destruct_trap(mach_port_name_t target,
		mach_port_name_t name, mach_port_delta_t srdelta,
		uint64_t guard)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_destruct_trap(%p, %p, %p, %p)\n",
			(void *)target, (void *)name, (void *)srdelta,
			(void *)guard);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_guard_trap(mach_port_name_t target,
		mach_port_name_t name, uint64_t guard, boolean_t strict)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_guard_trap(%p, %p, %p, %p)\n",
			(void *)target, (void *)name, (void *)guard,
			(void *)strict);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_unguard_trap(
		mach_port_name_t target, mach_port_name_t name, uint64_t guard)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_unguard_trap(%p, %p, %p)\n",
			(void *)target, (void *)name, (void *)guard);
#endif
	unimplemented();
}

kern_return_t
sys_mach_generate_activity_id(
		mach_port_name_t target, int count, uint64_t *activity_id)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_generate_activity_id(%p, %p, %p)\n",
			(void *)target, (void *)count, (void *)activity_id);
#endif
	unimplemented();
}

kern_return_t
sys_macx_swapon(uint64_t filename, int flags, int size, int priority)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "macx_swapon(%p, %p, %p, %p)\n", (void *)filename,
			(void *)flags, (void *)size, (void *)priority);
#endif
	unimplemented();
}

kern_return_t
sys_macx_swapoff(uint64_t filename, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "macx_swapoff(%p, %p)\n", (void *)filename,
			(void *)flags);
#endif
	unimplemented();
}

kern_return_t
sys_macx_triggers(
		int hi_water, int low_water, int flags, mach_port_t alert_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "macx_triggers(%p, %p, %p, %p)\n", (void *)hi_water,
			(void *)low_water, (void *)flags, (void *)alert_port);
#endif
	unimplemented();
}

kern_return_t
sys_macx_backing_store_suspend(boolean_t suspend)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "macx_backing_store_suspend(%p)\n", (void *)suspend);
#endif
	unimplemented();
}

kern_return_t
sys_macx_backing_store_recovery(int pid)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "macx_backing_store_recovery(%p)\n", (void *)pid);
#endif
	unimplemented();
}

boolean_t
sys_swtch_pri(int pri)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "swtch_pri(%p)\n", (void *)pri);
#endif
	unimplemented();
}

boolean_t
sys_swtch(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "swtch()\n");
#endif
	unimplemented();
}

kern_return_t
sys_thread_switch(mach_port_name_t thread_name, int option,
		mach_msg_timeout_t option_time)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "thread_switch(%p, %p, %p)\n", (void *)thread_name,
			(void *)option, (void *)option_time);
#endif
	unimplemented();
}

mach_port_name_t
sys_task_self_trap(void)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_self_trap()\n");
#endif
	return TASK_REPLY_PORT;
}

kern_return_t
sys_host_create_mach_voucher_trap(mach_port_name_t host,
		mach_voucher_attr_raw_recipe_array_t recipes, int recipes_size,
		mach_port_name_t *voucher)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_create_mach_voucher_trap(%p, %p, %p, %p)\n",
			(void *)host, (void *)recipes, (void *)recipes_size,
			(void *)voucher);
#endif
	/* TODO: Allocate and return a voucher */
	*(mach_port_name_t *)voucher = 0xb170babe;
	return KERN_SUCCESS;
}

kern_return_t
sys_mach_voucher_extract_attr_recipe_trap(mach_port_name_t voucher_name,
		mach_voucher_attr_key_t key,
		mach_voucher_attr_raw_recipe_t recipe,
		mach_msg_type_number_t *recipe_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_voucher_extract_attr_recipe_trap(%p, %p, %p, "
			"%p)\n",
			(void *)voucher_name, (void *)key, (void *)recipe,
			(void *)recipe_size);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_type_trap(ipc_space_t task, mach_port_name_t name,
		mach_port_type_t *ptype)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_mach_port_type_trap(%p, %p, %p)\n",
			(void *)task, (void *)name, (void *)ptype);
#endif
	unimplemented();
}

kern_return_t
sys__kernelrpc_mach_port_request_notification_trap(ipc_space_t task,
		mach_port_name_t name, mach_msg_id_t msgid,
		mach_port_mscount_t sync, mach_port_name_t notify,
		mach_msg_type_name_t notifyPoly, mach_port_name_t *previous)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"_kernelrpc_mach_port_request_notification_trap(%p, "
			"%p, %p, %p, %p, %p, %p)\n",
			(void *)task, (void *)name, (void *)msgid, (void *)sync,
			(void *)notify, (void *)notifyPoly, (void *)previous);
#endif
	unimplemented();
}

kern_return_t
sys_task_for_pid(mach_port_name_t target_tport, int pid, mach_port_name_t *t)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_for_pid(%p, %p, %p)\n", (void *)target_tport,
			(void *)pid, (void *)t);
#endif
	unimplemented();
}

kern_return_t
sys_task_name_for_pid(
		mach_port_name_t target_tport, int pid, mach_port_name_t *tn)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_name_for_pid(%p, %p, %p)\n", (void *)target_tport,
			(void *)pid, (void *)tn);
#endif
	unimplemented();
}

kern_return_t
sys_pid_for_task(mach_port_name_t t, int *x)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "pid_for_task(%p, %p)\n", (void *)t, (void *)x);
#endif
	unimplemented();
}

kern_return_t
sys_debug_control_port_for_pid(
		mach_port_name_t target_tport, int pid, mach_port_name_t *t)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "debug_control_port_for_pid(%p, %p, %p)\n",
			(void *)target_tport, (void *)pid, (void *)t);
#endif
	unimplemented();
}

kern_return_t
sys_mach_timebase_info_trap(void *info)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_timebase_info_trap(%p)\n", (void *)info);
#endif
	/* TODO: Handle */
	return KERN_FAILURE;
}

kern_return_t
sys_mach_wait_until_trap(uint64_t deadline)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_wait_until_trap(%p)\n", (void *)deadline);
#endif
	unimplemented();
}

kern_return_t
sys_mk_timer_create_trap(uint32_t dummy)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mk_timer_create_trap(%p)\n", (void *)dummy);
#endif
	unimplemented();
}

kern_return_t
sys_mk_timer_destroy_trap(mach_port_name_t name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mk_timer_destroy_trap(%p)\n", (void *)name);
#endif
	unimplemented();
}

kern_return_t
sys_mk_timer_arm_trap(mach_port_name_t name, uint64_t expire_time)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mk_timer_arm_trap(%p, %p)\n", (void *)name,
			(void *)expire_time);
#endif
	unimplemented();
}

kern_return_t
sys_mk_timer_cancel_trap(mach_port_name_t name, void *result_time)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mk_timer_cancel_trap(%p, %p)\n", (void *)name,
			(void *)result_time);
#endif
	unimplemented();
}

kern_return_t
sys_mk_timer_arm_leeway_trap(mach_port_name_t name, uint64_t mk_timer_flags,
		uint64_t expire_time, uint64_t mk_leeway)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mk_timer_arm_leeway_trap(%p, %p, %p, %p)\n",
			(void *)name, (void *)mk_timer_flags,
			(void *)expire_time, (void *)mk_leeway);
#endif
	unimplemented();
}

kern_return_t
sys_iokit_user_client_trap(void *userClientRef, uint32_t index, void *p1,
		void *p2, void *p3, void *p4, void *p5, void *p6)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"iokit_user_client_trap(%p, %p, %p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)userClientRef, (void *)index, (void *)p1,
			(void *)p2, (void *)p3, (void *)p4, (void *)p5,
			(void *)p6);
#endif
	unimplemented();
}

kern_return_t
sys_pfz_exit(int32_t dummy)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "iokit_user_client_trap(%p)\n", (void *)dummy);
#endif
	unimplemented();
}

uint64_t
sys_osfmk(unsigned long syscall, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		uint64_t arg4, uint64_t arg5, uint64_t arg6, uint64_t *sp)
{
	switch (syscall) {
	case 0x0:
		return sys_kern_invalid();
	case 0x1:
		return sys_kern_invalid();
	case 0x2:
		return sys_kern_invalid();
	case 0x3:
		return sys_kern_invalid();
	case 0x4:
		return sys_kern_invalid();
	case 0x5:
		return sys_kern_invalid();
	case 0x6:
		return sys_kern_invalid();
	case 0x7:
		return sys_kern_invalid();
	case 0x8:
		return sys_kern_invalid();
	case 0x9:
		return sys_kern_invalid();
	case 0xa:
		return sys__kernelrpc_mach_vm_allocate_trap(
				arg1, (void *)arg2, arg3, arg4);
	case 0xb:
		return sys__kernelrpc_mach_vm_purgable_control_trap(
				arg1, arg2, arg3, (void *)arg4);
	case 0xc:
		return sys__kernelrpc_mach_vm_deallocate_trap(arg1, arg2, arg3);
	case 0xd:
		return sys_kern_invalid();
	case 0xe:
		return sys__kernelrpc_mach_vm_protect_trap(
				arg1, arg2, arg3, arg4, arg5);
	case 0xf:
		return sys__kernelrpc_mach_vm_map_trap(
				arg1, (void *)arg2, arg3, arg4, arg5, arg6);
	case 0x10:
		return sys__kernelrpc_mach_port_allocate_trap(
				arg1, arg2, (void *)arg3);
	case 0x11:
		return sys_kern_invalid();
	case 0x12:
		return sys__kernelrpc_mach_port_deallocate_trap(arg1, arg2);
	case 0x13:
		return sys__kernelrpc_mach_port_mod_refs_trap(
				arg1, arg2, arg3, arg4);
	case 0x14:
		return sys__kernelrpc_mach_port_move_member_trap(
				arg1, arg2, arg3);
	case 0x15:
		return sys__kernelrpc_mach_port_insert_right_trap(
				arg1, arg2, arg3, arg4);
	case 0x16:
		return sys__kernelrpc_mach_port_insert_member_trap(
				arg1, arg2, arg3);
	case 0x17:
		return sys__kernelrpc_mach_port_extract_member_trap(
				arg1, arg2, arg3);
	case 0x18:
		return sys__kernelrpc_mach_port_construct_trap(
				arg1, (void *)arg2, arg3, (void *)arg4);
	case 0x19:
		return sys__kernelrpc_mach_port_destruct_trap(
				arg1, arg2, arg3, arg4);
	case 0x1a:
		return sys_mach_reply_port();
	case 0x1b:
		return sys_thread_self_trap();
	case 0x1c:
		return sys_task_self_trap();
	case 0x1d:
		return sys_host_self_trap();
	case 0x1e:
		return sys_kern_invalid();
	case 0x1f:
		return sys_mach_msg_trap((void *)arg1, arg2, arg3, arg4, arg5,
				arg6, sp[1]);
	case 0x20:
		return sys_mach_msg_overwrite_trap((void *)arg1, arg2, arg3,
				arg4, arg5, arg6, sp[1], (void *)sp[2], sp[3]);
	case 0x21:
		return sys_semaphore_signal_trap(arg1);
	case 0x22:
		return sys_semaphore_signal_all_trap(arg1);
	case 0x23:
		return sys_semaphore_signal_thread_trap(arg1, arg2);
	case 0x24:
		return sys_semaphore_wait_trap(arg1);
	case 0x25:
		return sys_semaphore_wait_signal_trap(arg1, arg2);
	case 0x26:
		return sys_semaphore_timedwait_trap(arg1, arg2, arg3);
	case 0x27:
		return sys_semaphore_timedwait_signal_trap(
				arg1, arg2, arg3, arg4);
	case 0x28:
		return sys__kernelrpc_mach_port_get_attributes_trap(
				arg1, arg2, arg3, (void *)arg4, (void *)arg5);
	case 0x29:
		return sys__kernelrpc_mach_port_guard_trap(
				arg1, arg2, arg3, arg4);
	case 0x2a:
		return sys__kernelrpc_mach_port_unguard_trap(arg1, arg2, arg3);
	case 0x2b:
		return sys_mach_generate_activity_id(arg1, arg2, (void *)arg3);
	case 0x2c:
		return sys_task_name_for_pid(arg1, arg2, (void *)arg3);
	case 0x2d:
		return sys_task_for_pid(arg1, arg2, (void *)arg3);
	case 0x2e:
		return sys_pid_for_task(arg1, (void *)arg2);
	case 0x2f:
		return sys_kern_invalid();
	case 0x30:
		return sys_macx_swapon(arg1, arg2, arg3, arg4);
	case 0x31:
		return sys_macx_swapoff(arg1, arg2);
	case 0x32:
		return sys_thread_get_special_reply_port();
	case 0x33:
		return sys_macx_triggers(arg1, arg2, arg3, arg4);
	case 0x34:
		return sys_macx_backing_store_suspend(arg1);
	case 0x35:
		return sys_macx_backing_store_recovery(arg1);
	case 0x36:
		return sys_kern_invalid();
	case 0x37:
		return sys_kern_invalid();
	case 0x38:
		return sys_kern_invalid();
	case 0x39:
		return sys_kern_invalid();
	case 0x3a:
		return sys_pfz_exit(arg1);
	case 0x3b:
		return sys_swtch_pri(arg1);
	case 0x3c:
		return sys_swtch();
	case 0x3d:
		return sys_thread_switch(arg1, arg2, arg3);
	case 0x3e:
		return sys_clock_sleep_trap(
				arg1, arg2, arg3, arg4, (void *)arg5);
	case 0x3f:
		return sys_kern_invalid();
	case 0x40:
		return sys_kern_invalid();
	case 0x41:
		return sys_kern_invalid();
	case 0x42:
		return sys_kern_invalid();
	case 0x43:
		return sys_kern_invalid();
	case 0x44:
		return sys_kern_invalid();
	case 0x45:
		return sys_kern_invalid();
	case 0x46:
		return sys_host_create_mach_voucher_trap(
				arg1, (void *)arg2, arg3, (void *)arg4);
	case 0x47:
		return sys_kern_invalid();
	case 0x48:
		return sys_mach_voucher_extract_attr_recipe_trap(
				arg1, arg2, (void *)arg3, (void *)arg4);
	case 0x49:
		return sys_kern_invalid();
	case 0x4a:
		return sys_kern_invalid();
	case 0x4b:
		return sys_kern_invalid();
	case 0x4c:
		return sys__kernelrpc_mach_port_type_trap(
				arg1, arg2, (void *)arg3);
	case 0x4d:
		return sys__kernelrpc_mach_port_request_notification_trap(arg1,
				arg2, arg3, arg4, arg5, arg6, (void *)sp[1]);
	case 0x4e:
		return sys_kern_invalid();
	case 0x4f:
		return sys_kern_invalid();
	case 0x50:
		return sys_kern_invalid();
	case 0x51:
		return sys_kern_invalid();
	case 0x52:
		return sys_kern_invalid();
	case 0x53:
		return sys_kern_invalid();
	case 0x54:
		return sys_kern_invalid();
	case 0x55:
		return sys_kern_invalid();
	case 0x56:
		return sys_kern_invalid();
	case 0x57:
		return sys_kern_invalid();
	case 0x58:
		return sys_kern_invalid();
	case 0x59:
		return sys_mach_timebase_info_trap((void *)arg1);
	case 0x5a:
		return sys_mach_wait_until_trap(arg1);
	case 0x5b:
		return sys_mk_timer_create_trap(arg1);
	case 0x5c:
		return sys_mk_timer_destroy_trap(arg1);
	case 0x5d:
		return sys_mk_timer_arm_trap(arg1, arg2);
	case 0x5e:
		return sys_mk_timer_cancel_trap(arg1, (void *)arg2);
	case 0x5f:
		return sys_mk_timer_arm_leeway_trap(arg1, arg2, arg3, arg4);
	case 0x60:
		return sys_debug_control_port_for_pid(arg1, arg2, (void *)arg3);
	case 0x61:
		return sys_kern_invalid();
	case 0x62:
		return sys_kern_invalid();
	case 0x63:
		return sys_kern_invalid();
	case 0x64:
		return sys_iokit_user_client_trap((void *)arg1, arg2,
				(void *)arg3, (void *)arg4, (void *)arg5,
				(void *)arg6, (void *)sp[1], (void *)sp[2]);
	case 0x65:
		return sys_kern_invalid();
	case 0x66:
		return sys_kern_invalid();
	case 0x67:
		return sys_kern_invalid();
	case 0x68:
		return sys_kern_invalid();
	case 0x69:
		return sys_kern_invalid();
	case 0x6a:
		return sys_kern_invalid();
	case 0x6b:
		return sys_kern_invalid();
	case 0x6c:
		return sys_kern_invalid();
	case 0x6d:
		return sys_kern_invalid();
	case 0x6e:
		return sys_kern_invalid();
	case 0x6f:
		return sys_kern_invalid();
	case 0x70:
		return sys_kern_invalid();
	case 0x71:
		return sys_kern_invalid();
	case 0x72:
		return sys_kern_invalid();
	case 0x73:
		return sys_kern_invalid();
	case 0x74:
		return sys_kern_invalid();
	case 0x75:
		return sys_kern_invalid();
	case 0x76:
		return sys_kern_invalid();
	case 0x77:
		return sys_kern_invalid();
	case 0x78:
		return sys_kern_invalid();
	case 0x79:
		return sys_kern_invalid();
	case 0x7a:
		return sys_kern_invalid();
	case 0x7b:
		return sys_kern_invalid();
	case 0x7c:
		return sys_kern_invalid();
	case 0x7d:
		return sys_kern_invalid();
	case 0x7e:
		return sys_kern_invalid();
	case 0x7f:
		return sys_kern_invalid();
	default:
#ifdef ENABLE_STRACE
		printf(">> Missing Mach system call: %#lx\n", syscall);
#endif
		abort();
	}
}
