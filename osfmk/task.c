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

#include <mach/mach.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "port.h"

kern_return_t
semaphore_create(task_t task, semaphore_t *semaphore, int policy, int value)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "semaphore_create(%p, %p, %p, %p)\n", (void *)task,
			(void *)semaphore, (void *)policy, (void *)value);
#endif
	/* TODO: Implement */
	return KERN_SUCCESS;
}

kern_return_t
task_restartable_ranges_register(task_t target_task,
		task_restartable_range_array_t ranges,
		mach_msg_type_number_t rangesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_restartable_ranges_register(%p, %p, %p)\n",
			(void *)target_task, (void *)ranges, (void *)rangesCnt);
#endif
	/* TODO: Implement */
	return KERN_SUCCESS;
}

#define TASK_BOOTSTRAP_PORT 4

kern_return_t
task_get_special_port(
		task_inspect_t task, int which_port, mach_port_t *special_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_get_special_port(%p, %p, %p)\n", (void *)task,
			(void *)which_port, (void *)special_port);
#endif
	if (which_port == TASK_BOOTSTRAP_PORT) {
		*special_port = BOOTSTRAP_PORT;
		return KERN_SUCCESS;
	}

	/* TODO: Implement */
	unimplemented();
}

kern_return_t
task_info(task_name_t target_task, task_flavor_t flavor,
		task_info_t task_info_out,
		mach_msg_type_number_t *task_info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "task_info(%p, %p, %p, %p)\n", (void *)target_task,
			(void *)flavor, (void *)task_info_out,
			(void *)task_info_outCnt);
#endif
	switch (flavor) {
	case TASK_AUDIT_TOKEN: {
		audit_token_t *audit_token_p = (audit_token_t *)task_info_out;
		memset(audit_token_p, 0, sizeof(audit_token_t));
		audit_token_p->val[5] = getpid();
		/* TODO: idversion_for_pid(getpid()); */
		audit_token_p->val[7] = 10;
		*task_info_outCnt = TASK_AUDIT_TOKEN_COUNT;
	} break;
	default:
		unimplemented();
	}

	return KERN_SUCCESS;
}

kern_return_t
task_create(task_t target_task, ledger_array_t ledgers,
		mach_msg_type_number_t ledgersCnt, boolean_t inherit_memory,
		task_t *child_task)
{
	unimplemented();
}

kern_return_t
task_terminate(task_t target_task)
{
	unimplemented();
}

kern_return_t
task_threads(task_inspect_t target_task, thread_act_array_t *act_list,
		mach_msg_type_number_t *act_listCnt)
{
	unimplemented();
}

kern_return_t
mach_ports_register(task_t target_task, mach_port_array_t init_port_set,
		mach_msg_type_number_t init_port_setCnt)
{
	/* TODO: Implement */
	return 0;
}

kern_return_t
mach_ports_lookup(task_t target_task, mach_port_array_t *init_port_set,
		mach_msg_type_number_t *init_port_setCnt)
{
	/* TODO: Implement */
	*init_port_setCnt = 0;
	return 0;
}

kern_return_t
task_set_info(task_t target_task, task_flavor_t flavor,
		task_info_t task_info_in,
		mach_msg_type_number_t task_info_inCnt)
{
	unimplemented();
}

kern_return_t
task_suspend(task_t target_task)
{
	unimplemented();
}

kern_return_t
task_resume(task_t target_task)
{
	unimplemented();
}

kern_return_t
task_set_special_port(task_t task, int which_port, mach_port_t special_port)
{
	/* TODO: Handle */
	return KERN_SUCCESS;
}

kern_return_t
thread_create(task_t parent_task, thread_act_t *child_act)
{
	unimplemented();
}

kern_return_t
thread_create_running(task_t parent_task, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt,
		thread_act_t *child_act)
{
	unimplemented();
}

kern_return_t
task_set_exception_ports(task_t task, exception_mask_t exception_mask,
		mach_port_t new_port, exception_behavior_t behavior,
		thread_state_flavor_t new_flavor)
{
	unimplemented();
}

kern_return_t
task_get_exception_ports(task_t task, exception_mask_t exception_mask,
		exception_mask_array_t masks, mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlers,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
	unimplemented();
}

kern_return_t
task_swap_exception_ports(task_t task, exception_mask_t exception_mask,
		mach_port_t new_port, exception_behavior_t behavior,
		thread_state_flavor_t new_flavor, exception_mask_array_t masks,
		mach_msg_type_number_t *masksCnt,
		exception_handler_array_t old_handlerss,
		exception_behavior_array_t old_behaviors,
		exception_flavor_array_t old_flavors)
{
	unimplemented();
}

kern_return_t
lock_set_create(task_t task, lock_set_t *new_lock_set, int n_ulocks, int policy)
{
	unimplemented();
}

kern_return_t
lock_set_destroy(task_t task, lock_set_t lock_set)
{
	unimplemented();
}

kern_return_t
semaphore_destroy(task_t task, semaphore_t semaphore)
{
	unimplemented();
}

kern_return_t
task_policy_set(task_policy_set_t task, task_policy_flavor_t flavor,
		task_policy_t policy_info,
		mach_msg_type_number_t policy_infoCnt)
{
	unimplemented();
}

kern_return_t
task_policy_get(task_policy_get_t task, task_policy_flavor_t flavor,
		task_policy_t policy_info,
		mach_msg_type_number_t *policy_infoCnt, boolean_t *get_default)
{
	unimplemented();
}

kern_return_t
task_sample(task_t task, mach_port_t reply)
{
	unimplemented();
}

kern_return_t
task_policy(task_t task, policy_t policy, policy_base_t base,
		mach_msg_type_number_t baseCnt, boolean_t set_limit,
		boolean_t change)
{
	unimplemented();
}

kern_return_t
task_set_emulation(task_t target_port, vm_address_t routine_entry_pt,
		int routine_number)
{
	unimplemented();
}

kern_return_t
task_get_emulation_vector(task_t task, int *vector_start,
		emulation_vector_t *emulation_vector,
		mach_msg_type_number_t *emulation_vectorCnt)
{
	unimplemented();
}

kern_return_t
task_set_emulation_vector(task_t task, int vector_start,
		emulation_vector_t emulation_vector,
		mach_msg_type_number_t emulation_vectorCnt)
{
	unimplemented();
}

kern_return_t
task_set_ras_pc(task_t target_task, vm_address_t basepc, vm_address_t boundspc)
{
	unimplemented();
}

kern_return_t
task_zone_info(task_inspect_t target_task, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, task_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt)
{
	unimplemented();
}

kern_return_t
task_assign(task_t task, processor_set_t new_set, boolean_t assign_threads)
{
	unimplemented();
}

kern_return_t
task_assign_default(task_t task, boolean_t assign_threads)
{
	unimplemented();
}

kern_return_t
task_get_assignment(task_inspect_t task, processor_set_name_t *assigned_set)
{
	unimplemented();
}

kern_return_t
task_set_policy(task_t task, processor_set_t pset, policy_t policy,
		policy_base_t base, mach_msg_type_number_t baseCnt,
		policy_limit_t limit, mach_msg_type_number_t limitCnt,
		boolean_t change)
{
	unimplemented();
}

kern_return_t
task_get_state(task_read_t task, thread_state_flavor_t flavor,
		thread_state_t old_state, mach_msg_type_number_t *old_stateCnt)
{
	unimplemented();
}

kern_return_t
task_set_state(task_t task, thread_state_flavor_t flavor,
		thread_state_t new_state, mach_msg_type_number_t new_stateCnt)
{
	unimplemented();
}

kern_return_t
task_set_phys_footprint_limit(task_t task, int new_limit, int *old_limit)
{
	unimplemented();
}

kern_return_t
task_suspend2(task_t target_task, task_suspension_token_t *suspend_token)
{
	unimplemented();
}

kern_return_t
task_resume2(task_suspension_token_t suspend_token)
{
	unimplemented();
}

kern_return_t
task_purgable_info(task_inspect_t task, task_purgable_info_t *stats)
{
	unimplemented();
}

kern_return_t
task_get_mach_voucher(task_read_t task, mach_voucher_selector_t which,
		ipc_voucher_t *voucher)
{
	unimplemented();
}

kern_return_t
task_set_mach_voucher(task_t task, ipc_voucher_t voucher)
{
	unimplemented();
}

kern_return_t
task_swap_mach_voucher(task_t task, ipc_voucher_t new_voucher,
		ipc_voucher_t *old_voucher)
{
	unimplemented();
}

kern_return_t
task_generate_corpse(task_t task, mach_port_t *corpse_task_port)
{
	unimplemented();
}

kern_return_t
task_map_corpse_info(task_t task, task_read_t corspe_task,
		vm_address_t *kcd_addr_begin, uint32_t *kcd_size)
{
	unimplemented();
}

kern_return_t
task_register_dyld_image_infos(task_t task,
		dyld_kernel_image_info_array_t dyld_images,
		mach_msg_type_number_t dyld_imagesCnt)
{
	unimplemented();
}

kern_return_t
task_unregister_dyld_image_infos(task_t task,
		dyld_kernel_image_info_array_t dyld_images,
		mach_msg_type_number_t dyld_imagesCnt)
{
	unimplemented();
}

kern_return_t
task_get_dyld_image_infos(task_read_t task,
		dyld_kernel_image_info_array_t *dyld_images,
		mach_msg_type_number_t *dyld_imagesCnt)
{
	unimplemented();
}

kern_return_t
task_register_dyld_shared_cache_image_info(task_t task,
		dyld_kernel_image_info_t dyld_cache_image, boolean_t no_cache,
		boolean_t private_cache)
{
	unimplemented();
}

kern_return_t
task_register_dyld_set_dyld_state(task_t task, uint8_t dyld_state)
{
	unimplemented();
}

kern_return_t
task_register_dyld_get_process_state(
		task_t task, dyld_kernel_process_info_t *dyld_process_state)
{
	unimplemented();
}

kern_return_t
task_map_corpse_info_64(task_t task, task_read_t corspe_task,
		mach_vm_address_t *kcd_addr_begin, mach_vm_size_t *kcd_size)
{
	unimplemented();
}

kern_return_t
task_inspect(task_inspect_t task, task_inspect_flavor_t flavor,
		task_inspect_info_t info_out,
		mach_msg_type_number_t *info_outCnt)
{
	unimplemented();
}

kern_return_t
task_get_exc_guard_behavior(
		task_inspect_t task, task_exc_guard_behavior_t *behavior)
{
	unimplemented();
}

kern_return_t
task_set_exc_guard_behavior(task_t task, task_exc_guard_behavior_t behavior)
{
	unimplemented();
}

kern_return_t
task_create_suid_cred(task_t task, suid_cred_path_t path, suid_cred_uid_t uid,
		suid_cred_t *delegation)
{
	unimplemented();
}
