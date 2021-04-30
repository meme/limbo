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
#include <stddef.h>
#include <stdint.h>

typedef size_t mach_msg_send_size_t;

uint64_t sys_osfmk(unsigned long syscall, uint64_t arg1, uint64_t arg2,
		uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
		uint64_t *sp);

int sys_kern_invalid(void);
mach_port_name_t sys_mach_reply_port(void);
mach_port_name_t sys_thread_get_special_reply_port(void);
mach_port_name_t sys_thread_self_trap(void);
mach_port_name_t sys_host_self_trap(void);
mach_msg_return_t sys_mach_msg_trap(mach_msg_header_t *msg,
		mach_msg_option_t option, mach_msg_size_t send_size,
		mach_msg_size_t rcv_size, mach_port_name_t rcv_name,
		mach_msg_timeout_t timeout, mach_port_name_t notify);

mach_msg_return_t sys_mach_msg_overwrite_trap(mach_msg_header_t *msg,
		mach_msg_option_t option, mach_msg_size_t send_size,
		mach_msg_size_t rcv_size, mach_port_name_t rcv_name,
		mach_msg_timeout_t timeout, mach_msg_priority_t priority,
		mach_msg_header_t *rcv_msg, mach_msg_size_t rcv_limit);
kern_return_t sys_semaphore_signal_trap(mach_port_name_t signal_name);
kern_return_t sys_semaphore_signal_all_trap(mach_port_name_t signal_name);
kern_return_t sys_semaphore_signal_thread_trap(
		mach_port_name_t signal_name, mach_port_name_t thread_name);
kern_return_t sys_semaphore_wait_trap(mach_port_name_t wait_name);
kern_return_t sys_semaphore_wait_signal_trap(
		mach_port_name_t wait_name, mach_port_name_t signal_name);
kern_return_t sys_semaphore_timedwait_trap(
		mach_port_name_t wait_name, unsigned int sec, clock_res_t nsec);
kern_return_t sys_semaphore_timedwait_signal_trap(mach_port_name_t wait_name,
		mach_port_name_t signal_name, unsigned int sec,
		clock_res_t nsec);
kern_return_t sys_clock_sleep_trap(mach_port_name_t clock_name,
		sleep_type_t sleep_type, int sleep_sec, int sleep_nsec,
		mach_timespec_t *wakeup_time);
kern_return_t sys__kernelrpc_mach_vm_allocate_trap(mach_port_name_t target,
		mach_vm_offset_t *addr, mach_vm_size_t size, int flags);
kern_return_t sys__kernelrpc_mach_vm_deallocate_trap(mach_port_name_t target,
		mach_vm_address_t address, mach_vm_size_t size);
kern_return_t sys__kernelrpc_mach_vm_protect_trap(mach_port_name_t target,
		mach_vm_address_t address, mach_vm_size_t size,
		boolean_t set_maximum, vm_prot_t new_protection);
kern_return_t sys__kernelrpc_mach_vm_map_trap(mach_port_name_t target,
		mach_vm_offset_t *address, mach_vm_size_t size,
		mach_vm_offset_t mask, int flags, vm_prot_t cur_protection);
kern_return_t sys__kernelrpc_mach_vm_purgable_control_trap(
		mach_port_name_t target, mach_vm_offset_t address,
		vm_purgable_t control, int *state);
kern_return_t sys__kernelrpc_mach_port_allocate_trap(mach_port_name_t target,
		mach_port_right_t right, mach_port_name_t *name);
kern_return_t sys__kernelrpc_mach_port_deallocate_trap(
		mach_port_name_t target, mach_port_name_t name);
kern_return_t sys__kernelrpc_mach_port_mod_refs_trap(mach_port_name_t target,
		mach_port_name_t name, mach_port_right_t right,
		mach_port_delta_t delta);
kern_return_t sys__kernelrpc_mach_port_move_member_trap(mach_port_name_t target,
		mach_port_name_t member, mach_port_name_t after);
kern_return_t sys__kernelrpc_mach_port_insert_right_trap(
		mach_port_name_t target, mach_port_name_t name,
		mach_port_name_t poly, mach_msg_type_name_t polyPoly);
kern_return_t sys__kernelrpc_mach_port_get_attributes_trap(
		mach_port_name_t target, mach_port_name_t name,
		mach_port_flavor_t flavor, mach_port_info_t port_info_out,
		mach_msg_type_number_t *port_info_outCnt);
kern_return_t sys__kernelrpc_mach_port_insert_member_trap(
		mach_port_name_t target, mach_port_name_t name,
		mach_port_name_t pset);
kern_return_t sys__kernelrpc_mach_port_extract_member_trap(
		mach_port_name_t target, mach_port_name_t name,
		mach_port_name_t pset);
kern_return_t sys__kernelrpc_mach_port_construct_trap(mach_port_name_t target,
		mach_port_options_t *options, uint64_t context,
		mach_port_name_t *name);
kern_return_t sys__kernelrpc_mach_port_destruct_trap(mach_port_name_t target,
		mach_port_name_t name, mach_port_delta_t srdelta,
		uint64_t guard);
kern_return_t sys__kernelrpc_mach_port_guard_trap(mach_port_name_t target,
		mach_port_name_t name, uint64_t guard, boolean_t strict);
kern_return_t sys__kernelrpc_mach_port_unguard_trap(
		mach_port_name_t target, mach_port_name_t name, uint64_t guard);
kern_return_t sys_mach_generate_activity_id(
		mach_port_name_t target, int count, uint64_t *activity_id);
kern_return_t sys_macx_swapon(
		uint64_t filename, int flags, int size, int priority);
kern_return_t sys_macx_swapoff(uint64_t filename, int flags);
kern_return_t sys_macx_triggers(
		int hi_water, int low_water, int flags, mach_port_t alert_port);
kern_return_t sys_macx_backing_store_suspend(boolean_t suspend);
kern_return_t sys_macx_backing_store_recovery(int pid);
boolean_t sys_swtch_pri(int pri);
boolean_t sys_swtch(void);
kern_return_t sys_thread_switch(mach_port_name_t thread_name, int option,
		mach_msg_timeout_t option_time);
mach_port_name_t sys_task_self_trap(void);
kern_return_t sys_host_create_mach_voucher_trap(mach_port_name_t host,
		mach_voucher_attr_raw_recipe_array_t recipes, int recipes_size,
		mach_port_name_t *voucher);
kern_return_t sys_mach_voucher_extract_attr_recipe_trap(
		mach_port_name_t voucher_name, mach_voucher_attr_key_t key,
		mach_voucher_attr_raw_recipe_t recipe,
		mach_msg_type_number_t *recipe_size);
kern_return_t sys__kernelrpc_mach_port_type_trap(ipc_space_t task,
		mach_port_name_t name, mach_port_type_t *ptype);
kern_return_t sys__kernelrpc_mach_port_request_notification_trap(
		ipc_space_t task, mach_port_name_t name, mach_msg_id_t msgid,
		mach_port_mscount_t sync, mach_port_name_t notify,
		mach_msg_type_name_t notifyPoly, mach_port_name_t *previous);
kern_return_t sys_task_for_pid(
		mach_port_name_t target_tport, int pid, mach_port_name_t *t);
kern_return_t sys_task_name_for_pid(
		mach_port_name_t target_tport, int pid, mach_port_name_t *tn);
kern_return_t sys_pid_for_task(mach_port_name_t t, int *x);
kern_return_t sys_debug_control_port_for_pid(
		mach_port_name_t target_tport, int pid, mach_port_name_t *t);
