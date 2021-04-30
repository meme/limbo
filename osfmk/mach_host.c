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

#include "port.h"

kern_return_t
host_info(host_t host, host_flavor_t flavor, host_info_t info,
		mach_msg_type_number_t *count)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_info(%p, %p, %p, %p)\n", (void *)host,
			(void *)flavor, (void *)info, (void *)count);
#endif
	switch (flavor) {
	case HOST_BASIC_INFO: {
		host_basic_info_t basic_info = (host_basic_info_t)info;
		memset(basic_info, 0, sizeof(*basic_info));
		basic_info->cpu_type = CPU_TYPE_X86_64;
		basic_info->cpu_subtype = CPU_SUBTYPE_X86_64_ALL;
		*count = 1;
	} break;
	case HOST_PRIORITY_INFO: {
		host_priority_info_t priority_info = (host_priority_info_t)info;
		memset(priority_info, 0, sizeof(*priority_info));
		/* TODO: This struct should be non-zero */
		*count = 1;
	} break;
	case HOST_PREFERRED_USER_ARCH: {
		host_preferred_user_arch_t preferred_arch
				= (host_preferred_user_arch_t)info;
		preferred_arch->cpu_type = CPU_TYPE_X86_64;
		preferred_arch->cpu_subtype = CPU_SUBTYPE_X86_ALL;
		*count = 1;
	} break;
	default:
		unimplemented();
	}

	return KERN_SUCCESS;
}

kern_return_t
host_kernel_version(host_t host, kernel_version_t kernel_version)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_kernel_version(%p, %p)\n", (void *)host,
			(void *)kernel_version);
#endif
	unimplemented();
}

kern_return_t
_host_page_size(host_t host, vm_size_t *out_page_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_host_page_size(%p, %p)\n", (void *)host,
			(void *)out_page_size);
#endif
	unimplemented();
}

kern_return_t
mach_memory_object_memory_entry(host_t host, boolean_t internal, vm_size_t size,
		vm_prot_t permission, memory_object_t pager,
		mach_port_t *entry_handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_memory_object_memory_entry(%p, %p, %p, %p, %p, "
			"%p)\n",
			(void *)host, (void *)internal, (void *)size,
			(void *)permission, (void *)pager,
			(void *)entry_handle);
#endif
	unimplemented();
}

kern_return_t
host_processor_info(host_t host, processor_flavor_t flavor,
		natural_t *out_processor_count,
		processor_info_array_t *out_processor_info,
		mach_msg_type_number_t *out_processor_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_processor_info(%p, %p, %p, %p, %p)\n",
			(void *)host, (void *)flavor,
			(void *)out_processor_count, (void *)out_processor_info,
			(void *)out_processor_infoCnt);
#endif
	unimplemented();
}

kern_return_t
host_get_io_master(host_t host, io_master_t *io_master)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_get_io_master(%p, %p)\n", (void *)host,
			(void *)io_master);
#endif
	unimplemented();
}

kern_return_t
kmod_get_info(host_t host, kmod_args_t *modules,
		mach_msg_type_number_t *modulesCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "kmod_get_info(%p, %p, %p)\n", (void *)host,
			(void *)modules, (void *)modulesCnt);
#endif
	unimplemented();
}

kern_return_t
host_virtual_physical_table_info(host_t host, hash_info_bucket_array_t *info,
		mach_msg_type_number_t *infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_virtual_physical_table_info(%p, %p, %p)\n",
			(void *)host, (void *)info, (void *)infoCnt);
#endif
	unimplemented();
}

kern_return_t
processor_set_default(host_t host, processor_set_name_t *default_set)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "processor_set_default(%p, %p)\n", (void *)host,
			(void *)default_set);
#endif
	unimplemented();
}

kern_return_t
processor_set_create(host_t host, processor_set_t *new_set,
		processor_set_name_t *new_name)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "processor_set_create(%p, %p, %p)\n", (void *)host,
			(void *)new_set, (void *)new_name);
#endif
	unimplemented();
}

kern_return_t
mach_memory_object_memory_entry_64(host_t host, boolean_t internal,
		memory_object_size_t size, vm_prot_t permission,
		memory_object_t pager, mach_port_t *entry_handle)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"mach_memory_object_memory_entry_64(%p, %p, %p, %p, "
			"%p, %p)\n",
			(void *)host, (void *)internal, (void *)size,
			(void *)permission, (void *)pager,
			(void *)entry_handle);
#endif
	unimplemented();
}

kern_return_t
host_statistics(host_t host_priv, host_flavor_t flavor,
		host_info_t host_info_out,
		mach_msg_type_number_t *host_info_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_statistics(%p, %p, %p, %p)\n", (void *)host_priv,
			(void *)flavor, (void *)host_info_out,
			(void *)host_info_outCnt);
#endif
	unimplemented();
}

kern_return_t
host_request_notification(
		host_t host, host_flavor_t notify_type, mach_port_t notify_port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_request_notification(%p, %p, %p)\n", (void *)host,
			(void *)notify_type, (void *)notify_port);
#endif
	unimplemented();
}

kern_return_t
host_lockgroup_info(host_t host, lockgroup_info_array_t *lockgroup_info,
		mach_msg_type_number_t *lockgroup_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_lockgroup_info(%p, %p, %p)\n", (void *)host,
			(void *)lockgroup_info, (void *)lockgroup_infoCnt);
#endif
	unimplemented();
}

kern_return_t
host_statistics64(host_t host_priv, host_flavor_t flavor,
		host_info64_t host_info64_out,
		mach_msg_type_number_t *host_info64_outCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_statistics64(%p, %p, %p, %p)\n",
			(void *)host_priv, (void *)flavor,
			(void *)host_info64_out, (void *)host_info64_outCnt);
#endif
	unimplemented();
}

kern_return_t
mach_zone_info(host_priv_t host, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, mach_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_zone_info(%p, %p, %p, %p, %p)\n", (void *)host,
			(void *)names, (void *)namesCnt, (void *)info,
			(void *)infoCnt);
#endif
	unimplemented();
}

kern_return_t
_kernelrpc_host_create_mach_voucher(host_t host,
		mach_voucher_attr_raw_recipe_array_t recipes,
		mach_msg_type_number_t recipesCnt, ipc_voucher_t *voucher)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "_kernelrpc_host_create_mach_voucher(%p, %p, %p, %p)\n",
			(void *)host, (void *)recipes, (void *)recipesCnt,
			(void *)voucher);
#endif
	unimplemented();
}

kern_return_t
host_register_mach_voucher_attr_manager(host_t host,
		mach_voucher_attr_manager_t attr_manager,
		mach_voucher_attr_value_handle_t default_value,
		mach_voucher_attr_key_t *new_key,
		ipc_voucher_attr_control_t *new_attr_control)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"host_register_mach_voucher_attr_manager(%p, %p, %p, "
			"%p, %p)\n",
			(void *)host, (void *)attr_manager,
			(void *)default_value, (void *)new_key,
			(void *)new_attr_control);
#endif
	unimplemented();
}

kern_return_t
host_register_well_known_mach_voucher_attr_manager(host_t host,
		mach_voucher_attr_manager_t attr_manager,
		mach_voucher_attr_value_handle_t default_value,
		mach_voucher_attr_key_t key,
		ipc_voucher_attr_control_t *new_attr_control)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"host_register_well_known_mach_voucher_attr_manager(%p,"
			" %p, %p, %p, %p)\n",
			(void *)host, (void *)attr_manager,
			(void *)default_value, (void *)key,
			(void *)new_attr_control);
#endif
	unimplemented();
}

kern_return_t
host_set_atm_diagnostic_flag(host_t host, uint32_t diagnostic_flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_set_atm_diagnostic_flag(%p, %p)\n", (void *)host,
			(void *)diagnostic_flag);
#endif
	unimplemented();
}

kern_return_t
mach_memory_info(host_priv_t host, mach_zone_name_array_t *names,
		mach_msg_type_number_t *namesCnt, mach_zone_info_array_t *info,
		mach_msg_type_number_t *infoCnt,
		mach_memory_info_array_t *memory_info,
		mach_msg_type_number_t *memory_infoCnt)
{
#ifdef ENABLE_STRACE
	fprintf(stderr,
			"host_register_well_known_mach_voucher_attr_manager(%p,"
			" %p, %p, %p, %p, %p, %p)\n",
			(void *)host, (void *)names, (void *)namesCnt,
			(void *)info, (void *)infoCnt, (void *)memory_info,
			(void *)memory_infoCnt);
#endif
	unimplemented();
}

kern_return_t
host_set_multiuser_config_flags(host_priv_t host_priv, uint32_t multiuser_flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_set_multiuser_config_flags(%p, %p)\n",
			(void *)host_priv, (void *)multiuser_flags);
#endif
	unimplemented();
}

kern_return_t
mach_zone_info_for_zone(
		host_priv_t host, mach_zone_name_t name, mach_zone_info_t *info)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "mach_zone_info_for_zone(%p, %p, %p)\n", (void *)host,
			(void *)&name, (void *)info);
#endif
	unimplemented();
}

kern_return_t
host_get_clock_service(host_t host, clock_id_t clock_id, clock_serv_t *clock)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_get_clock_service(%p, %p, %p)\n", (void *)host,
			(void *)clock_id, (void *)clock);
#endif
	if (clock_id == SYSTEM_CLOCK) {
		*clock = SYSTEM_CLOCK_PORT;
		return KERN_SUCCESS;
	}

	unimplemented();
}

kern_return_t
host_get_special_port(
		host_priv_t host_priv, int node, int which, mach_port_t *port)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "host_get_special_port(%p, %p, %p, %p)\n",
			(void *)host_priv, (void *)node, (void *)which,
			(void *)port);
#endif
	if (node == -1 && which == 1) {
		*port = HOST_SPECIAL_PORT_1;
		return KERN_SUCCESS;
	}

	unimplemented();
}
