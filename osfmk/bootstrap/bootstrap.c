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

#include "bootstrap.h"

kern_return_t
bootstrap_check_in(mach_port_t bootstrap_port, name_t service_name,
		mach_port_t *service_port)
{
	abort();
}

kern_return_t
bootstrap_register(mach_port_t bootstrap_port, name_t service_name,
		mach_port_t service_port)
{
	abort();
}

kern_return_t
bootstrap_look_up(mach_port_t bootstrap_port, name_t service_name,
		mach_port_t *service_port)
{
	abort();
}

kern_return_t
bootstrap_look_up_array(mach_port_t bootstrap_port, name_array_t service_names,
		mach_msg_type_number_t service_namesCnt,
		mach_port_array_t *service_ports,
		mach_msg_type_number_t *service_portsCnt,
		boolean_t *all_services_known)
{
	abort();
}

kern_return_t
bootstrap_status(mach_port_t bootstrap_port, name_t service_name,
		boolean_t *service_active)
{
	abort();
}

kern_return_t
bootstrap_info(mach_port_t bootstrap_port, name_array_t *service_names,
		mach_msg_type_number_t *service_namesCnt,
		name_array_t *server_names,
		mach_msg_type_number_t *server_namesCnt,
		bool_array_t *service_active,
		mach_msg_type_number_t *service_activeCnt)
{
	abort();
}

kern_return_t
bootstrap_subset(mach_port_t bootstrap_port, mach_port_t requestor_port,
		mach_port_t *subset_port)
{
	abort();
}

kern_return_t
bootstrap_create_service(mach_port_t bootstrap_port, name_t service_name,
		mach_port_t *service_port)
{
	abort();
}
