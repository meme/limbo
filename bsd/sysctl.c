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

#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach/i386/thread_status.h>
#include <mach/mach.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef void *user_addr_t;

/* TODO: This really shouldn't be here */
struct __darwin_timeval {
	time_t tv_sec;
	suseconds_t tv_usec;
};

#define CTL_UNSPEC  0
#define CTL_KERN    1
#define CTL_VM      2
#define CTL_VFS     3
#define CTL_NET     4
#define CTL_DEBUG   5
#define CTL_HW      6
#define CTL_MACHDEP 7
#define CTL_USER    8
#define CTL_MAXID   9

#define KERN_OSTYPE             1
#define KERN_OSRELEASE          2
#define KERN_OSREV              3
#define KERN_VERSION            4
#define KERN_MAXVNODES          5
#define KERN_MAXPROC            6
#define KERN_MAXFILES           7
#define KERN_ARGMAX             8
#define KERN_SECURELVL          9
#define KERN_HOSTNAME           10
#define KERN_HOSTID             11
#define KERN_CLOCKRATE          12
#define KERN_VNODE              13
#define KERN_PROC               14
#define KERN_FILE               15
#define KERN_PROF               16
#define KERN_POSIX1             17
#define KERN_NGROUPS            18
#define KERN_JOB_CONTROL        19
#define KERN_SAVED_IDS          20
#define KERN_BOOTTIME           21
#define KERN_NISDOMAINNAME      22
#define KERN_DOMAINNAME         KERN_NISDOMAINNAME
#define KERN_MAXPARTITIONS      23
#define KERN_KDEBUG             24
#define KERN_UPDATEINTERVAL     25
#define KERN_OSRELDATE          26
#define KERN_NTP_PLL            27
#define KERN_BOOTFILE           28
#define KERN_MAXFILESPERPROC    29
#define KERN_MAXPROCPERUID      30
#define KERN_DUMPDEV            31
#define KERN_IPC                32
#define KERN_DUMMY              33
#define KERN_PS_STRINGS         34
#define KERN_USRSTACK32         35
#define KERN_LOGSIGEXIT         36
#define KERN_SYMFILE            37
#define KERN_PROCARGS           38
#define KERN_NETBOOT            40
#define KERN_SYSV               42
#define KERN_AFFINITY           43
#define KERN_TRANSLATE          44
#define KERN_CLASSIC            KERN_TRANSLATE
#define KERN_EXEC               45
#define KERN_CLASSICHANDLER     KERN_EXEC
#define KERN_AIOMAX             46
#define KERN_AIOPROCMAX         47
#define KERN_AIOTHREADS         48
#define KERN_PROCARGS2          49
#define KERN_COREFILE           50
#define KERN_COREDUMP           51
#define KERN_SUGID_COREDUMP     52
#define KERN_PROCDELAYTERM      53
#define KERN_SHREG_PRIVATIZABLE 54
#define KERN_LOW_PRI_WINDOW     56
#define KERN_LOW_PRI_DELAY      57
#define KERN_POSIX              58
#define KERN_USRSTACK64         59
#define KERN_NX_PROTECTION      60
#define KERN_TFP                61
#define KERN_PROCNAME           62
#define KERN_THALTSTACK         63
#define KERN_SPECULATIVE_READS  64
#define KERN_OSVERSION          65
#define KERN_SAFEBOOT           66
#define KERN_RAGEVNODE          68
#define KERN_TTY                69
#define KERN_CHECKOPENEVT       70
#define KERN_THREADNAME         71
#define KERN_MAXID              72

#define KERN_PROC_ALL     0
#define KERN_PROC_PID     1
#define KERN_PROC_PGRP    2
#define KERN_PROC_SESSION 3
#define KERN_PROC_TTY     4
#define KERN_PROC_UID     5
#define KERN_PROC_RUID    6
#define KERN_PROC_LCID    7

static int
sysctl_kern1(int code, void *old, size_t *oldlenp)
{
	switch (code) {
	case KERN_OSTYPE:
		*(void **)old = "Darwin";
		*oldlenp = sizeof("Darwin");
		break;
	case KERN_OSRELEASE:
		*(void **)old = "20.3.0";
		*oldlenp = sizeof("20.3.0");
		break;
	case KERN_VERSION:
		*(void **)old = "Darwin Kernel Version 20.3.0: Thu Jan 21 "
				"00:06:51 PST 2021; "
				"root:xnu-7195.81.3~1/RELEASE_ARM64_T8101";
		*oldlenp = sizeof("Darwin Kernel Version 20.3.0: Thu Jan 21 "
				  "00:06:51 PST 2021; "
				  "root:xnu-7195.81.3~1/RELEASE_ARM64_T8101");
		break;
	case KERN_USRSTACK64:
		*(void **)old = VM_USRSTACK64;
		*oldlenp = sizeof(void *);
		break;
	case KERN_OSVERSION:
		*(void **)old = "20D91";
		*oldlenp = sizeof("20D91");
		break;
	case KERN_HOSTNAME:
		/* TODO: gethostname(2) */
		*(void **)old = "linux";
		*oldlenp = sizeof("linux");
		break;
	case KERN_ARGMAX:
		*(int *)old = 0x100000;
		*oldlenp = sizeof(int);
		break;
	case KERN_BOOTTIME: {
		struct __darwin_timeval *tv = (struct __darwin_timeval *)old;
		tv->tv_sec = 0;
		tv->tv_usec = 0;
		*oldlenp = sizeof(struct __darwin_timeval);
	} break;
	case KERN_SECURELVL:
		*(int *)old = 0;
		*oldlenp = sizeof(int);
		break;
	default:
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> Missing sysctl kern.*: %d\n", code);
#endif
		unimplemented();
	}

	return 0;
}

#define HW_MACHINE      1
#define HW_MODEL        2
#define HW_NCPU         3
#define HW_BYTEORDER    4
#define HW_PHYSMEM      5
#define HW_USERMEM      6
#define HW_PAGESIZE     7
#define HW_DISKNAMES    8
#define HW_DISKSTATS    9
#define HW_EPOCH        10
#define HW_FLOATINGPT   11
#define HW_MACHINE_ARCH 12
#define HW_VECTORUNIT   13
#define HW_BUS_FREQ     14
#define HW_CPU_FREQ     15
#define HW_CACHELINE    16
#define HW_L1ICACHESIZE 17
#define HW_L1DCACHESIZE 18
#define HW_L2SETTINGS   19
#define HW_L2CACHESIZE  20
#define HW_L3SETTINGS   21
#define HW_L3CACHESIZE  22
#define HW_TB_FREQ      23
#define HW_MEMSIZE      24
#define HW_AVAILCPU     25
#define HW_TARGET       26
#define HW_PRODUCT      27
#define HW_MAXID        28

static int
sysctl_hw1(int code, void *old, size_t *oldlenp)
{
	switch (code) {
	case HW_PAGESIZE:
		*(int *)old = 0x1000;
		*oldlenp = sizeof(int);
		break;
	case HW_MACHINE:
		*(void **)old = "x86_64";
		*oldlenp = sizeof("x86_64");
		break;
	case HW_NCPU:
		*(int *)old = 12;
		*oldlenp = sizeof(int);
		break;
	default:
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> Missing sysctl hw.*: %d\n", code);
#endif
		unimplemented();
	}

	return 0;
}

int
sys_sysctl(int *name, uint32_t namelen, void *old, size_t *oldlenp, void *new,
		size_t newlen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sysctl(%p, %p, %p, %p, %p, %p)\n", (void *)name,
			(void *)namelen, (void *)old, (void *)oldlenp,
			(void *)new, (void *)newlen);
#endif
	/* TODO: For now, you may not set anything */
	if (new != NULL) {
		unimplemented();
	}

	if (namelen == 2) {
		int group = name[0];
		int specific = name[1];

		switch (group) {
		case CTL_KERN:
			return sysctl_kern1(specific, old, oldlenp);
		case CTL_HW:
			return sysctl_hw1(specific, old, oldlenp);
		default:
#ifdef ENABLE_STRACE
			fprintf(stderr, ">> Missing sysctl group: %d\n", group);
#endif
			unimplemented();
		}
	} else if (namelen == 4) {
		int group = name[0];
		int type = name[1];
		int subtype = name[2];
		int unk = name[3];

		if (group == CTL_KERN && type == KERN_PROC
				&& subtype == KERN_PROC_PID) {
			/* TODO: Implement */
			(void)unk;
			return 0;
		}

#ifdef ENABLE_STRACE
		fprintf(stderr,
				">> Missing sysctl: group: %d, type: %d, "
				"subtype: %d\n",
				group, type, subtype);
#endif
	}

	unimplemented();
}

int
sys_sys_sysctlbyname(const char *name, size_t namelen, void *old,
		size_t *oldlenp, void *new, size_t newlen)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_sysctlbyname(\"%s\", %p, %p, %p, %p, %p)\n", name,
			(void *)namelen, (void *)old, (void *)oldlenp,
			(void *)new, (void *)newlen);
#endif
	if (strncmp(name, "kern.boottime", namelen) == 0) {
		return sysctl_kern1(KERN_BOOTTIME, old, oldlenp);
	} else if (strncmp(name, "kern.secure_kernel", namelen) == 0) {
		return sysctl_kern1(KERN_SECURELVL, old, oldlenp);
	} else if (strncmp(name, "hw.physicalcpu", namelen) == 0) {
		return sysctl_hw1(HW_NCPU, old, oldlenp);
	}

	unimplemented();
}
