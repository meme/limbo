#ifndef	_bootstrap_user_
#define	_bootstrap_user_

/* Module bootstrap */

#include <string.h>
#include <mach/ndr.h>
#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/notify.h>
#include <mach/mach_types.h>
#include <mach/message.h>
#include <mach/mig_errors.h>
#include <mach/port.h>
	
/* BEGIN VOUCHER CODE */

#ifndef KERNEL
#if defined(__has_include)
#if __has_include(<mach/mig_voucher_support.h>)
#ifndef USING_VOUCHERS
#define USING_VOUCHERS
#endif
#ifndef __VOUCHER_FORWARD_TYPE_DECLS__
#define __VOUCHER_FORWARD_TYPE_DECLS__
#ifdef __cplusplus
extern "C" {
#endif
	extern boolean_t voucher_mach_msg_set(mach_msg_header_t *msg) __attribute__((weak_import));
#ifdef __cplusplus
}
#endif
#endif // __VOUCHER_FORWARD_TYPE_DECLS__
#endif // __has_include(<mach/mach_voucher_types.h>)
#endif // __has_include
#endif // !KERNEL
	
/* END VOUCHER CODE */

	
/* BEGIN MIG_STRNCPY_ZEROFILL CODE */

#if defined(__has_include)
#if __has_include(<mach/mig_strncpy_zerofill_support.h>)
#ifndef USING_MIG_STRNCPY_ZEROFILL
#define USING_MIG_STRNCPY_ZEROFILL
#endif
#ifndef __MIG_STRNCPY_ZEROFILL_FORWARD_TYPE_DECLS__
#define __MIG_STRNCPY_ZEROFILL_FORWARD_TYPE_DECLS__
#ifdef __cplusplus
extern "C" {
#endif
	extern int mig_strncpy_zerofill(char *dest, const char *src, int len) __attribute__((weak_import));
#ifdef __cplusplus
}
#endif
#endif /* __MIG_STRNCPY_ZEROFILL_FORWARD_TYPE_DECLS__ */
#endif /* __has_include(<mach/mig_strncpy_zerofill_support.h>) */
#endif /* __has_include */
	
/* END MIG_STRNCPY_ZEROFILL CODE */


#ifdef AUTOTEST
#ifndef FUNCTION_PTR_T
#define FUNCTION_PTR_T
typedef void (*function_ptr_t)(mach_port_t, char *, mach_msg_type_number_t);
typedef struct {
        char            *name;
        function_ptr_t  function;
} function_table_entry;
typedef function_table_entry   *function_table_t;
#endif /* FUNCTION_PTR_T */
#endif /* AUTOTEST */

#ifndef	bootstrap_MSG_COUNT
#define	bootstrap_MSG_COUNT	11
#endif	/* bootstrap_MSG_COUNT */

#include <mach/std_types.h>
#include <mach/mig.h>
#include "bootstrap_defs.h"

#ifdef __BeforeMigUserHeader
__BeforeMigUserHeader
#endif /* __BeforeMigUserHeader */

#include <sys/cdefs.h>
__BEGIN_DECLS


/* Routine bootstrap_check_in */
#ifdef	mig_external
mig_external
#else
extern
#endif	/* mig_external */
kern_return_t bootstrap_check_in
(
	mach_port_t bootstrap_port,
	name_t service_name,
	mach_port_t *service_port
);

/* Routine bootstrap_register */
#ifdef	mig_external
mig_external
#else
extern
#endif	/* mig_external */
kern_return_t bootstrap_register
(
	mach_port_t bootstrap_port,
	name_t service_name,
	mach_port_t service_port
);

/* Routine bootstrap_look_up */
#ifdef	mig_external
mig_external
#else
extern
#endif	/* mig_external */
kern_return_t bootstrap_look_up
(
	mach_port_t bootstrap_port,
	name_t service_name,
	mach_port_t *service_port
);

/* Routine bootstrap_look_up_array */
#ifdef	mig_external
mig_external
#else
extern
#endif	/* mig_external */
kern_return_t bootstrap_look_up_array
(
	mach_port_t bootstrap_port,
	name_array_t service_names,
	mach_msg_type_number_t service_namesCnt,
	mach_port_array_t *service_ports,
	mach_msg_type_number_t *service_portsCnt,
	boolean_t *all_services_known
);

/* Routine bootstrap_status */
#ifdef	mig_external
mig_external
#else
extern
#endif	/* mig_external */
kern_return_t bootstrap_status
(
	mach_port_t bootstrap_port,
	name_t service_name,
	boolean_t *service_active
);

/* Routine bootstrap_info */
#ifdef	mig_external
mig_external
#else
extern
#endif	/* mig_external */
kern_return_t bootstrap_info
(
	mach_port_t bootstrap_port,
	name_array_t *service_names,
	mach_msg_type_number_t *service_namesCnt,
	name_array_t *server_names,
	mach_msg_type_number_t *server_namesCnt,
	bool_array_t *service_active,
	mach_msg_type_number_t *service_activeCnt
);

/* Routine bootstrap_subset */
#ifdef	mig_external
mig_external
#else
extern
#endif	/* mig_external */
kern_return_t bootstrap_subset
(
	mach_port_t bootstrap_port,
	mach_port_t requestor_port,
	mach_port_t *subset_port
);

/* Routine bootstrap_create_service */
#ifdef	mig_external
mig_external
#else
extern
#endif	/* mig_external */
kern_return_t bootstrap_create_service
(
	mach_port_t bootstrap_port,
	name_t service_name,
	mach_port_t *service_port
);

__END_DECLS

/********************** Caution **************************/
/* The following data types should be used to calculate  */
/* maximum message sizes only. The actual message may be */
/* smaller, and the position of the arguments within the */
/* message layout may vary from what is presented here.  */
/* For example, if any of the arguments are variable-    */
/* sized, and less than the maximum is sent, the data    */
/* will be packed tight in the actual message to reduce  */
/* the presence of holes.                                */
/********************** Caution **************************/

/* typedefs for all requests */

#ifndef __Request__bootstrap_subsystem__defined
#define __Request__bootstrap_subsystem__defined

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		name_t service_name;
	} __Request__bootstrap_check_in_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t service_port;
		/* end of the kernel processed data */
		NDR_record_t NDR;
		name_t service_name;
	} __Request__bootstrap_register_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		name_t service_name;
	} __Request__bootstrap_look_up_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_ool_descriptor_t service_names;
		/* end of the kernel processed data */
		NDR_record_t NDR;
		mach_msg_type_number_t service_namesCnt;
	} __Request__bootstrap_look_up_array_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		name_t service_name;
	} __Request__bootstrap_status_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
	} __Request__bootstrap_info_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t requestor_port;
		/* end of the kernel processed data */
	} __Request__bootstrap_subset_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		name_t service_name;
	} __Request__bootstrap_create_service_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif
#endif /* !__Request__bootstrap_subsystem__defined */

/* union of all requests */

#ifndef __RequestUnion__bootstrap_subsystem__defined
#define __RequestUnion__bootstrap_subsystem__defined
union __RequestUnion__bootstrap_subsystem {
	__Request__bootstrap_check_in_t Request_bootstrap_check_in;
	__Request__bootstrap_register_t Request_bootstrap_register;
	__Request__bootstrap_look_up_t Request_bootstrap_look_up;
	__Request__bootstrap_look_up_array_t Request_bootstrap_look_up_array;
	__Request__bootstrap_status_t Request_bootstrap_status;
	__Request__bootstrap_info_t Request_bootstrap_info;
	__Request__bootstrap_subset_t Request_bootstrap_subset;
	__Request__bootstrap_create_service_t Request_bootstrap_create_service;
};
#endif /* !__RequestUnion__bootstrap_subsystem__defined */
/* typedefs for all replies */

#ifndef __Reply__bootstrap_subsystem__defined
#define __Reply__bootstrap_subsystem__defined

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t service_port;
		/* end of the kernel processed data */
	} __Reply__bootstrap_check_in_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		kern_return_t RetCode;
	} __Reply__bootstrap_register_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t service_port;
		/* end of the kernel processed data */
	} __Reply__bootstrap_look_up_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_ool_ports_descriptor_t service_ports;
		/* end of the kernel processed data */
		NDR_record_t NDR;
		mach_msg_type_number_t service_portsCnt;
		boolean_t all_services_known;
	} __Reply__bootstrap_look_up_array_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		NDR_record_t NDR;
		kern_return_t RetCode;
		boolean_t service_active;
	} __Reply__bootstrap_status_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_ool_descriptor_t service_names;
		mach_msg_ool_descriptor_t server_names;
		mach_msg_ool_descriptor_t service_active;
		/* end of the kernel processed data */
		NDR_record_t NDR;
		mach_msg_type_number_t service_namesCnt;
		mach_msg_type_number_t server_namesCnt;
		mach_msg_type_number_t service_activeCnt;
	} __Reply__bootstrap_info_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t subset_port;
		/* end of the kernel processed data */
	} __Reply__bootstrap_subset_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif

#ifdef  __MigPackStructs
#pragma pack(push, 4)
#endif
	typedef struct {
		mach_msg_header_t Head;
		/* start of the kernel processed data */
		mach_msg_body_t msgh_body;
		mach_msg_port_descriptor_t service_port;
		/* end of the kernel processed data */
	} __Reply__bootstrap_create_service_t __attribute__((unused));
#ifdef  __MigPackStructs
#pragma pack(pop)
#endif
#endif /* !__Reply__bootstrap_subsystem__defined */

/* union of all replies */

#ifndef __ReplyUnion__bootstrap_subsystem__defined
#define __ReplyUnion__bootstrap_subsystem__defined
union __ReplyUnion__bootstrap_subsystem {
	__Reply__bootstrap_check_in_t Reply_bootstrap_check_in;
	__Reply__bootstrap_register_t Reply_bootstrap_register;
	__Reply__bootstrap_look_up_t Reply_bootstrap_look_up;
	__Reply__bootstrap_look_up_array_t Reply_bootstrap_look_up_array;
	__Reply__bootstrap_status_t Reply_bootstrap_status;
	__Reply__bootstrap_info_t Reply_bootstrap_info;
	__Reply__bootstrap_subset_t Reply_bootstrap_subset;
	__Reply__bootstrap_create_service_t Reply_bootstrap_create_service;
};
#endif /* !__RequestUnion__bootstrap_subsystem__defined */

#ifndef subsystem_to_name_map_bootstrap
#define subsystem_to_name_map_bootstrap \
    { "bootstrap_check_in", 402 },\
    { "bootstrap_register", 403 },\
    { "bootstrap_look_up", 404 },\
    { "bootstrap_look_up_array", 405 },\
    { "bootstrap_status", 407 },\
    { "bootstrap_info", 408 },\
    { "bootstrap_subset", 409 },\
    { "bootstrap_create_service", 410 }
#endif

#ifdef __AfterMigUserHeader
__AfterMigUserHeader
#endif /* __AfterMigUserHeader */

#endif	 /* _bootstrap_user_ */
