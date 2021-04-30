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

#include <asm/prctl.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <ucontext.h>
#include <unistd.h>

#include "bsd/handler.h"
#include "commpage.h"
#include "linker.h"
#include "mdep/handler.h"
#include "osfmk/handler.h"
#include "shared_cache.h"

/* Never allow system calls from outside our binary region */
static const uint8_t selector = SYSCALL_DISPATCH_FILTER_BLOCK;

/* Temporary TLS for dyld */
static char dyld_ls[0x1000];

int arch_prctl(int, unsigned long);
static int commpage_mmap(void);

/*
 * System calls in Darwin are split into classes, as follows:
 * SYSCALL_CLASS_NONE  0   Invalid
 * SYSCALL_CLASS_MACH  1   Mach
 * SYSCALL_CLASS_UNIX  2   Unix/BSD
 * SYSCALL_CLASS_MDEP  3   Machine-dependent
 * SYSCALL_CLASS_DIAG  4   Diagnostics
 *
 * The system call number is the 24-bit left shift: (2 << 24) is to call
 * SYSCALL_CLASS_UNIX
 */

#define SYSCALL_CLASS_NONE 0
#define SYSCALL_CLASS_MACH (1 << 24)
#define SYSCALL_CLASS_UNIX (2 << 24)
#define SYSCALL_CLASS_MDEP (3 << 24)
#define SYSCALL_CLASS_DIAG (4 << 24)

static void
handle_syscall(int sig, siginfo_t *info, void *ucontext)
{
	ucontext_t *context = (ucontext_t *)ucontext;
	greg_t *regs = context->uc_mcontext.gregs;

	/*
	 * RDI, RSI, RDX, R10, R8, R9 and then spilling to the stack
	 *
	 * Presumably due to how the Linux system call trapping is implemented,
	 * the 7th argument lands on the 2nd slot of the stack (1st is LR)
	 *
	 * Returns in RAX
	 */

	uint64_t arg1 = regs[REG_RDI];
	uint64_t arg2 = regs[REG_RSI];
	uint64_t arg3 = regs[REG_RDX];
	uint64_t arg4 = regs[REG_R10];
	uint64_t arg5 = regs[REG_R8];
	uint64_t arg6 = regs[REG_R9];
	uint64_t *sp = (uint64_t *)regs[REG_RSP];

	/* Remove all status flags */
	regs[REG_EFL] = 0;

	unsigned long syscall = info->si_syscall;
	if (syscall >= SYSCALL_CLASS_MACH && syscall < SYSCALL_CLASS_UNIX) {
		regs[REG_RAX] = sys_osfmk(syscall - SYSCALL_CLASS_MACH, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
	} else if (syscall >= SYSCALL_CLASS_UNIX
			&& syscall < SYSCALL_CLASS_MDEP) {
		regs[REG_RAX] = sys_bsd(syscall - SYSCALL_CLASS_UNIX, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
	} else if (syscall >= SYSCALL_CLASS_MDEP
			&& syscall < SYSCALL_CLASS_DIAG) {
		regs[REG_RAX] = sys_mdep(syscall - SYSCALL_CLASS_MDEP, arg1,
				arg2, arg3, arg4, arg5, arg6, sp);
	} else {
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> Missing system call: %#lx", syscall);
#endif
		abort();
	}
}

static unsigned long SYSINFO_EHDR;

static int
unmap_vdso(void)
{
	unsigned long vdso = SYSINFO_EHDR;
	unsigned long vvar = vdso - PAGE_SIZE * 4;

	/* On Darwin, mappings overlap with the Linux [vdso] and [vvar] special
	 * mappings which are required for certain glibc functionality.
	 * By unmapping them, we free up the address space, but we also
	 * permanently break wrappers such as gettimeofday, etc.
	 */
	if (munmap((void *)vvar, PAGE_SIZE * 4) == -1) {
		perror("munmap");
		return 1;
	}

	if (munmap((void *)vdso, PAGE_SIZE * 2) == -1) {
		perror("munmap");
		return 1;
	}

	return 0;
}

int
stage2(int argc, char *argv[], char *envp[])
{
	if (argc < 2) {
		fprintf(stderr, "limbo: no path\n");
		return 1;
	}

	if (unmap_vdso()) {
		return 1;
	}

	/* Register a SIGSYS handler for trapping syscalls */
	struct sigaction act;
	sigset_t mask;
	memset(&act, 0, sizeof(act));
	sigemptyset(&mask);

	act.sa_sigaction = handle_syscall;
	act.sa_flags = SA_SIGINFO | SA_NODEFER;
	act.sa_mask = mask;

	if (sigaction(SIGSYS, &act, NULL) == -1) {
		perror("sigaction");
		goto error;
	}

	/* Map the shared cache into our memory space, persisted across fork()
	 */
	int cache_fd;
	size_t cache_size;
	void *cache = linker_mmap(
			"/System/Library/dyld/dyld_shared_cache_x86_64",
			&cache_size, &cache_fd);
	if (cache == NULL) {
		fprintf(stderr, "limbo: cannot read shared cache\n");
		return 1;
	}

	shared_cache_mmap(cache, cache_fd);
	if (shared_cache_start == NULL) {
		fprintf(stderr,
				"limbo: could not map and rebase shared "
				"cache\n");
		return 1;
	}

	close(cache_fd);
	munmap(cache, cache_size);

	/* Map the target executable and determine its interpreter */
	const char *dylinker_path = NULL;
	uint8_t *exe_base = linker_link(argv[1], &dylinker_path, NULL);
	if (exe_base == NULL || dylinker_path == NULL) {
		fprintf(stderr, "limbo: failed to load binary\n");
		return 1;
	}

	/* Map the target executable's interpreter (dyld) */
	uintptr_t entry = 0;
	uint8_t *dyld_base = linker_link(dylinker_path, NULL, &entry);
	if (dyld_base == NULL || entry == 0) {
		fprintf(stderr,
				"limbo: failed to load binary "
				"interpreter\n");
		return 1;
	}

	/* Set up the stack in the way that dyld expects */
	char stack_guard[8];
	char stack_guard_str[16 + 1] = {0};
	if (getrandom(stack_guard, sizeof(stack_guard), GRND_NONBLOCK)
			!= sizeof(stack_guard)) {
		fprintf(stderr,
				"limbo: failed to get random data for stack "
				"guard\n");
		goto error;
	}
	for (uint32_t i = 0; i < sizeof(stack_guard); i++) {
		sprintf((char *)&stack_guard_str + i * 2, "%02x",
				(unsigned char)stack_guard[i]);
	}
	stack_guard_str[16] = '\0';

	/* Map 64mb of stack with  MAP_GROWSDOWN so that the stack automatically
	 * grows down */
	uintptr_t stack_base = (uintptr_t)mmap(
			(void *)((uintptr_t)VM_USRSTACK64 - 64 * 1024 * 1024),
			64 * 1024 * 1024, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_FIXED | MAP_ANON | MAP_GROWSDOWN, -1,
			0);
	if (stack_base == (uintptr_t)MAP_FAILED) {
		perror("mmap");
	}
	stack_base = (uintptr_t)VM_USRSTACK64;

	/* Set up the stack_guard= value */
	unsigned long applev;
	unsigned long applev0;
	applev0 = applev = (stack_base
			-= (strlen("stack_guard=") + sizeof(stack_guard_str)));
	memcpy((void *)stack_base, "stack_guard=", strlen("stack_guard="));
	memcpy((void *)(stack_base + strlen("stack_guard=")), stack_guard_str,
			sizeof(stack_guard_str));
	/* MUST HAVE 0x */
	const char *junk = "ptr_munge=0x1337";
	applev = (stack_base -= strlen(junk) + 1);
	memcpy((void *)stack_base, junk, strlen(junk) + 1);

	int envc;
	for (envc = 0; envp[envc] != NULL; envc++)
		;

	int applec = 3;
	int apple_argc = argc - 1; /* Do not include ./limbo in the argv */
	stack_base -= (applec + 1) * sizeof(void *); /* Apple env pointers */
	stack_base -= (envc + 1) * sizeof(void *);   /* Env pointers */
	stack_base -= (apple_argc + 1) * sizeof(void *); /* Arg pointers */
	stack_base -= sizeof(long) * 2;                  /* Main frame */
	/* TODO: Determine the correct alignment by consulting the XNU kernel
	 * sources */
	stack_base = (stack_base & ~0xf);

	unsigned long *sp = (unsigned long *)stack_base;
	/* Main frame */
	/* TODO: This is the default load address for echo, we need to figure
	 * out how to slide it */
	*sp++ = (unsigned long)exe_base;
	*sp++ = (unsigned long)apple_argc;

	/* Arguments */
	for (int i = 0; i < apple_argc; i++) {
		/* +1 because we want to skip ./limbo */
		*sp++ = (unsigned long)argv[i + 1];
	}
	*sp++ = 0; /* End of arguments */

	/* Environment */
	for (int i = 0; i < envc; i++) {
		*sp++ = (unsigned long)envp[i];
	}
	*sp++ = 0; /* End of environment */

	/* Apple environment */
	*sp++ = (unsigned long)argv[1];
	*sp++ = (unsigned long)applev0;
	*sp++ = (unsigned long)applev;
	*sp++ = 0; /* End of environment */

	if (commpage_mmap()) {
		goto error;
	}

	/* Set up the temporary zero-ed TLS storage for dyld */
	memset(dyld_ls, 0, sizeof(dyld_ls));
	arch_prctl(ARCH_SET_GS, (unsigned long)dyld_ls);

	/* In the filldir$INODE64 routine in dyld, there is a reallocf(NULL,
	 * 0x1000) which doesn't check the NULL to avoid a memmove(dest, NULL,
	 * 0x1000). I really don't understand what is happening so the only
	 * conclusion I could draw is that the kernel maps a zeroed zero page.
	 * This requires a sysctl. If this is in fact the problem, then we
	 * should replace this with a userfaultfd and unregister it after dyld
	 * is done. sudo sysctl -w vm.mmap_min_addr=0 sudo setsebool
	 * mmap_low_allowed true */
	if (mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE | MAP_ANON | MAP_FIXED,
			    -1, 0)
			== MAP_FAILED) {
		perror("limbo: cannot map zero page, ensure `sysctl -w "
		       "vm.mmap_min_addr=0' is set and SELinux is configured "
		       "`setsebool mmap_low_allowed true': mmap:");
		goto error;
	}

	asm volatile("mov %0, %%rsp; jmp *%1" ::"r"(stack_base), "r"(entry));
	__builtin_unreachable();
error:
	exit(1);
}

static int
commpage_mmap(void)
{
	void *commpage = mmap((void *)_COMM_PAGE_START_ADDRESS,
			_COMM_PAGE_AREA_LENGTH, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_FIXED | MAP_ANON, -1, 0);
	if (commpage == MAP_FAILED) {
		perror("mmap");
		return 1;
	}

	/* TODO: Initialize the entire commpage */
	*(uint16_t *)_COMM_PAGE_VERSION = _COMM_PAGE_THIS_VERSION;
	*(uint32_t *)_COMM_PAGE_NT_GENERATION = 1;
	*(uint8_t *)_COMM_PAGE_ACTIVE_CPUS = 12;
	*(uint8_t *)_COMM_PAGE_LOGICAL_CPUS = 24;
	*(uint8_t *)_COMM_PAGE_PHYSICAL_CPUS = 12;
	*(uint8_t *)_COMM_PAGE_USER_PAGE_SHIFT_64 = 12;
	*(uint64_t *)_COMM_PAGE_MEMORY_SIZE = 17179869184;

	return 0;
}

static ucontext_t stage0_context;
static ucontext_t stage1_context;
static ucontext_t stage2_context;

static char stage1_stack[0x1000];

static const uintptr_t STACK_BASE = 0x80000000;
static uint64_t stack_start;
static uint64_t stack_end;

static void
stage1(int argc, char *argv[], char *envp[])
{
	uintptr_t stack_size = stack_end - stack_start;

	if (mremap((void *)stack_start, stack_size, stack_size,
			    MREMAP_FIXED | MREMAP_MAYMOVE, STACK_BASE)
			== MAP_FAILED) {
		perror("mremap");
		exit(1);
	}

	if (getcontext(&stage2_context)) {
		perror("getcontext");
		exit(1);
	}

	/* TODO: Set the stack pointer past the [envp] so that the data is not
	 * overwritten on entry */
	stage2_context.uc_stack.ss_sp = (void *)(STACK_BASE - 0x8000);
	stage2_context.uc_stack.ss_size = stack_size - 0x8000;
	stage2_context.uc_link = &stage1_context;

	char **sargv = (char **)(((uintptr_t)argv - stack_start) + STACK_BASE);
	char **senvp = (char **)(((uintptr_t)envp - stack_start) + STACK_BASE);

	for (int i = 0; i < argc; i++) {
		*(uintptr_t *)&sargv[i] -= stack_start;
		*(uintptr_t *)&sargv[i] += STACK_BASE;
	}

	for (char **env = senvp; *env; env++) {
		*(uintptr_t *)env -= stack_start;
		*(uintptr_t *)env += STACK_BASE;
	}

	makecontext(&stage2_context, (void (*)())(void *)stage2, 3, argc, sargv,
			senvp);

	if (swapcontext(&stage1_context, &stage2_context) == -1) {
		perror("swapcontext");
	}

	exit(1);
}

int
main(int argc, char *argv[], char *envp[])
{
	/* Enumerate the program headers of the executable to determine the
	 * region for which we should NOT trap all system calls */
	Elf64_Phdr *phdrs = (Elf64_Phdr *)getauxval(AT_PHDR);
	if (phdrs == NULL) {
		perror("getauxval");
		return 1;
	}

	unsigned long e_phnum = getauxval(AT_PHNUM);
	if (e_phnum == 0) {
		perror("getauxval");
		return 1;
	}

	SYSINFO_EHDR = getauxval(AT_SYSINFO_EHDR);
	if (SYSINFO_EHDR == 0) {
		perror("getauxval");
		return 1;
	}

	for (uint32_t i = 0; i < e_phnum; i++) {
		Elf64_Phdr phdr = phdrs[i];
		if (phdr.p_type == PT_LOAD && phdr.p_flags & PF_X) {
			if (prctl(PR_SET_SYSCALL_USER_DISPATCH,
					    PR_SYS_DISPATCH_ON, phdr.p_vaddr,
					    phdr.p_memsz, &selector)) {
				perror("prctl");
				return 1;
			}
		}
	}

	/* Find beginning and end of the stack */
	FILE *f = fopen("/proc/self/maps", "r");
	if (f == NULL) {
		perror("limbo: cannot open /proc/self/maps");
		return 1;
	}

	char buffer[1024];
	while (fgets(buffer, sizeof(buffer), f) != NULL) {
		uint64_t start, end;
		char mode[5];
		uint32_t offset;
		char device[8];
		char inode[12];
		char path[256];
		sscanf(buffer, "%lx-%lx %4s %x %7s %11s %255s\n", &start, &end,
				mode, &offset, device, inode, path);
		if (!strncmp(path, "[stack]", sizeof(path))) {
			stack_start = start;
			stack_end = end;
		}
	}
	fclose(f);

	if (getcontext(&stage1_context)) {
		perror("getcontext");
		return 1;
	}

	stage1_context.uc_stack.ss_sp = stage1_stack;
	stage1_context.uc_stack.ss_size = sizeof(stage1_stack);
	stage1_context.uc_link = &stage0_context;

	makecontext(&stage1_context, (void (*)())stage1, 3, argc, argv, envp);

	if (swapcontext(&stage0_context, &stage1_context) == -1) {
		perror("swapcontext");
	}

	__builtin_unreachable();
}
