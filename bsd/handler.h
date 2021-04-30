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

typedef void *user_addr_t;
typedef size_t user_size_t;
typedef ssize_t user_ssize_t;

uint64_t sys_bsd(unsigned long syscall, uint64_t arg1, uint64_t arg2,
		uint64_t arg3, uint64_t arg4, uint64_t arg5, uint64_t arg6,
		uint64_t *sp);

int sys_nosys(void);
int __attribute__((noreturn)) sys_exit(int rval);
int sys_fork(void);
user_ssize_t sys_read(int fd, user_addr_t cbuf, user_size_t nbyte);
user_ssize_t sys_write(int fd, user_addr_t cbuf, user_size_t nbyte);
int sys_open(user_addr_t path, int flags, int mode);
int sys_sys_close(int fd);
int sys_wait4(int pid, user_addr_t status, int options, user_addr_t rusage);
int sys_enosys(void);
int sys_link(user_addr_t path, user_addr_t link);
int sys_unlink(user_addr_t path);
int sys_chdir(user_addr_t path);
int sys_fchdir(int fd);
int sys_mknod(user_addr_t path, int mode, int dev);
int sys_chmod(user_addr_t path, int mode);
int sys_chown(user_addr_t path, int uid, int gid);
int sys_getfsstat(user_addr_t buf, int bufsize, int flags);
int sys_getpid(void);
int sys_setuid(void *uid);
int sys_getuid(void);
int sys_geteuid(void);
int sys_ptrace(int req, uint64_t pid, void *addr, int data);
int sys_recvmsg(int s, void *msg, int flags);
int sys_sendmsg(int s, void *msg, int flags);
int sys_recvfrom(int s, void *buf, size_t len, int flags, void *from,
		int *fromlenaddr);
int sys_accept(int s, void *name, void *anamelen);
int sys_getpeername(int fdes, void *asa, void *alen);
int sys_getsockname(int fdes, void *asa, void *alen);
int sys_access(user_addr_t path, int flags);
int sys_chflags(char *path, int flags);
int sys_fchflags(int fd, int flags);
int sys_sync(void);
int sys_kill(int pid, int signum, int posix);
int sys_getppid(void);
int sys_sys_dup(uint32_t fd);
int sys_pipe(int pipefd[2]);
int sys_getegid(void);
int sys_sigaction(int signum, void *nsa, void *osa);
int sys_getgid(void);
int sys_sigprocmask(int how, user_addr_t mask, user_addr_t omask);
int sys_getlogin(char *namebuf, uint32_t namelen);
int sys_setlogin(char *namebuf);
int sys_acct(char *path);
int sys_sigpending(void *osv);
int sys_sigaltstack(void *nss, void *oss);
int sys_ioctl(int fd, uint64_t com, void *data);
int sys_reboot(int opt, char *msg);
int sys_revoke(char *path);
int sys_symlink(char *path, char *link);
int sys_readlink(char *path, char *buf, int count);
int sys_execve(char *fname, char **argp, char **envp);
int sys_umask(int newmask);
int sys_chroot(user_addr_t path);
int sys_msync(void *addr, size_t len, int flags);
int sys_vfork(void);
int sys_munmap(void *addr, size_t len);
int sys_mprotect(void *addr, size_t len, int prot);
int sys_madvise(void *addr, size_t len, int behav);
int sys_mincore(user_addr_t addr, user_size_t len, user_addr_t vec);
int sys_getgroups(uint32_t gidsetsize, void *gidset);
int sys_setgroups(uint32_t gidsetsize, void *gidset);
int sys_getpgrp(void);
int sys_setpgid(int pid, int pgid);
int sys_setitimer(uint32_t which, void *itv, void *oitv);
int sys_swapon(void);
int sys_getitimer(uint32_t which, void *itv);
int sys_sys_getdtablesize(void);
int sys_sys_dup2(uint32_t from, uint32_t to);
int sys_sys_fcntl(int fd, int cmd, long arg);
int sys_select(int nd, uint32_t *in, uint32_t *ou, uint32_t *ex, void *tv);
int sys_fsync(int fd);
int sys_setpriority(int which, void *who, int prio);
int sys_socket(int domain, int type, int protocol);
int sys_connect(int s, void *name, void *namelen);
int sys_getpriority(int which, void *who);
int sys_bind(int s, void *name, void *namelen);
int sys_setsockopt(int s, int level, int name, void *val, void *valsize);
int sys_listen(int s, int backlog);
int sys_sigsuspend(void *mask);
int sys_gettimeofday(void *tp, void *tzp, uint64_t *mach_absolute_time);
int sys_getrusage(int who, void *rusage);
int sys_getsockopt(int s, int level, int name, void *val, void *avalsize);
user_ssize_t sys_readv(int fd, void *iovp, uint32_t iovcnt);
user_ssize_t sys_writev(int fd, void *iovp, uint32_t iovcnt);
int sys_settimeofday(void *tv, void *tzp);
int sys_fchown(int fd, int uid, int gid);
int sys_fchmod(int fd, int mode);
int sys_setreuid(void *ruid, void *euid);
int sys_setregid(void *rgid, void *egid);
int sys_rename(char *from, char *to);
int sys_sys_flock(int fd, int how);
int sys_mkfifo(user_addr_t path, int mode);
int sys_sendto(int s, void *buf, size_t len, int flags, void *to, void *tolen);
int sys_shutdown(int s, int how);
int sys_socketpair(int domain, int type, int protocol, int *rsv);
int sys_mkdir(user_addr_t path, int mode);
int sys_rmdir(char *path);
int sys_utimes(char *path, void *tptr);
int sys_futimes(int fd, void *tptr);
int sys_adjtime(void *delta, void *olddelta);
int sys_gethostuuid(unsigned char *uuid_buf, void *timeoutp);
int sys_setsid(void);
int sys_getpgid(uint64_t pid);
int sys_setprivexec(int flag);
user_ssize_t sys_pread(
		int fd, user_addr_t buf, user_size_t nbyte, off_t offset);
user_ssize_t sys_pwrite(
		int fd, user_addr_t buf, user_size_t nbyte, off_t offset);
int sys_statfs(char *path, void *buf);
int sys_fstatfs(int fd, void *buf);
int sys_unmount(user_addr_t path, int flags);
int sys_quotactl(const char *path, int cmd, int uid, void *arg);
int sys_mount(char *type, char *path, int flags, void *data);
int sys_csops(uint64_t pid, uint32_t ops, user_addr_t useraddr,
		user_size_t usersize);
int sys_csops_audittoken(uint64_t pid, uint32_t ops, user_addr_t useraddr,
		user_size_t usersize, user_addr_t uaudittoken);
int sys_waitid(void *idtype, void *id, void *infop, int options);
int sys_kdebug_typefilter(void **addr, size_t *size);
uint64_t sys_kdebug_trace_string(
		uint32_t debugid, uint64_t str_id, const char *str);
int sys_kdebug_trace64(uint32_t code, uint64_t arg1, uint64_t arg2,
		uint64_t arg3, uint64_t arg4);
int sys_kdebug_trace(uint32_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3,
		uint64_t arg4);
int sys_setgid(void *gid);
int sys_setegid(void *egid);
int sys_seteuid(void *euid);
int sys_sigreturn(void *uctx, int infostyle, user_addr_t token);
int sys_thread_selfcounts(int type, user_addr_t buf, user_size_t nbytes);
int sys_fdatasync(int fd);
int sys_stat(user_addr_t path, user_addr_t ub);
int sys_sys_fstat(int fd, user_addr_t ub);
int sys_lstat(user_addr_t path, user_addr_t ub);
int sys_pathconf(char *path, int name);
int sys_sys_fpathconf(int fd, int name);
int sys_getrlimit(uint32_t which, void *rlp);
int sys_setrlimit(uint32_t which, void *rlp);
int sys_getdirentries(int fd, char *buf, uint32_t count, long *basep);
user_addr_t sys_mmap(
		void *addr, size_t len, int prot, int flags, int fd, off_t pos);
off_t sys_lseek(int fd, off_t offset, int whence);
int sys_truncate(char *path, off_t length);
int sys_ftruncate(int fd, off_t length);
int sys_sysctl(int *name, uint32_t namelen, void *old, size_t *oldlenp,
		void *new, size_t newlen);
int sys_mlock(void *addr, size_t len);
int sys_munlock(void *addr, size_t len);
int sys_undelete(user_addr_t path);
int sys_open_dprotected_np(
		user_addr_t path, int flags, int class, int dpflags, int mode);
user_ssize_t sys_fsgetpath_ext(user_addr_t buf, size_t bufsize,
		user_addr_t fsid, uint64_t objid, uint32_t options);
int sys_getattrlist(const char *path, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options);
int sys_setattrlist(const char *path, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options);
int sys_getdirentriesattr(int fd, void *alist, void *buffer, size_t buffersize,
		void *count, void *basep, void *newstate, uint64_t options);
int sys_exchangedata(const char *path1, const char *path2, uint64_t options);
int sys_searchfs(const char *path, void *searchblock, uint32_t *nummatches,
		uint32_t scriptcode, uint32_t options, void *state);
int sys_delete(user_addr_t path);
int sys_copyfile(char *from, char *to, int mode, int flags);
int sys_fgetattrlist(int fd, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options);
int sys_fsetattrlist(int fd, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options);
int sys_poll(void *fds, uint32_t nfds, int timeout);
user_ssize_t sys_getxattr(user_addr_t path, user_addr_t attrname,
		user_addr_t value, size_t size, uint32_t position, int options);
user_ssize_t sys_fgetxattr(int fd, user_addr_t attrname, user_addr_t value,
		size_t size, uint32_t position, int options);
int sys_setxattr(user_addr_t path, user_addr_t attrname, user_addr_t value,
		size_t size, uint32_t position, int options);
int sys_fsetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size,
		uint32_t position, int options);
int sys_removexattr(user_addr_t path, user_addr_t attrname, int options);
int sys_fremovexattr(int fd, user_addr_t attrname, int options);
user_ssize_t sys_listxattr(user_addr_t path, user_addr_t namebuf,
		size_t bufsize, int options);
user_ssize_t sys_flistxattr(
		int fd, user_addr_t namebuf, size_t bufsize, int options);
int sys_fsctl(const char *path, uint64_t cmd, void *data, uint32_t options);
int sys_initgroups(uint32_t gidsetsize, void *gidset, int gmuid);
int sys_posix_spawn(void *pid, const char *path, void *adesc, char **argv,
		char **envp);
int sys_ffsctl(int fd, uint64_t cmd, void *data, uint32_t options);
int sys_minherit(void *addr, size_t len, int inherit);
int sys_semsys(uint32_t which, int a2, int a3, int a4, int a5);
int sys_msgsys(uint32_t which, int a2, int a3, int a4, int a5);
int sys_shmsys(uint32_t which, int a2, int a3, int a4);
int sys_semctl(int semid, int semnum, int cmd, void *arg);
int sys_semget(void *key, int nsems, int semflg);
int sys_semop(int semid, void *sops, int nsops);
int sys_msgctl(int msqid, int cmd, void *buf);
int sys_msgget(void *key, int msgflg);
int sys_msgsnd(int msqid, void *msgp, size_t msgsz, int msgflg);
user_ssize_t sys_msgrcv(
		int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg);
user_addr_t sys_shmat(int shmid, void *shmaddr, int shmflg);
int sys_shmctl(int shmid, int cmd, void *buf);
int sys_shmdt(void *shmaddr);
int sys_shmget(void *key, size_t size, int shmflg);
int sys_shm_open(const char *name, int oflag, int mode);
int sys_shm_unlink(const char *name);
user_addr_t sys_sem_open(const char *name, int oflag, int mode, int value);
int sys_sem_close(void *sem);
int sys_sem_unlink(const char *name);
int sys_sem_wait(void *sem);
int sys_sem_trywait(void *sem);
int sys_sem_post(void *sem);
int sys_sys_sysctlbyname(const char *name, size_t namelen, void *old,
		size_t *oldlenp, void *new, size_t newlen);
int sys_open_extended(user_addr_t path, int flags, void *uid, void *gid,
		int mode, user_addr_t xsecurity);
int sys_umask_extended(int newmask, user_addr_t xsecurity);
int sys_stat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size);
int sys_lstat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size);
int sys_sys_fstat_extended(int fd, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size);
int sys_chmod_extended(user_addr_t path, void *uid, void *gid, int mode,
		user_addr_t xsecurity);
int sys_fchmod_extended(
		int fd, void *uid, void *gid, int mode, user_addr_t xsecurity);
int sys_access_extended(user_addr_t entries, size_t size, user_addr_t results,
		void *uid);
int sys_settid(void *uid, void *gid);
int sys_gettid(void *uidp, void *gidp);
int sys_setsgroups(int setlen, user_addr_t guidset);
int sys_getsgroups(user_addr_t setlen, user_addr_t guidset);
int sys_setwgroups(int setlen, user_addr_t guidset);
int sys_getwgroups(user_addr_t setlen, user_addr_t guidset);
int sys_mkfifo_extended(user_addr_t path, void *uid, void *gid, int mode,
		user_addr_t xsecurity);
int sys_mkdir_extended(user_addr_t path, void *uid, void *gid, int mode,
		user_addr_t xsecurity);
int sys_shared_region_check_np(uint64_t *start_address);
int sys_vm_pressure_monitor(int wait_for_pressure, int nsecs_monitored,
		uint32_t *pages_reclaimed);
int sys_getsid(uint64_t pid);
int sys_settid_with_pid(uint64_t pid, int assume);
int sys_aio_fsync(int op, user_addr_t aiocbp);
user_ssize_t sys_aio_return(user_addr_t aiocbp);
int sys_aio_suspend(user_addr_t aiocblist, int nent, user_addr_t timeoutp);
int sys_aio_cancel(int fd, user_addr_t aiocbp);
int sys_aio_error(user_addr_t aiocbp);
int sys_aio_read(user_addr_t aiocbp);
int sys_aio_write(user_addr_t aiocbp);
int sys_lio_listio(int mode, user_addr_t aiocblist, int nent, user_addr_t sigp);
int sys_iopolicysys(int cmd, void *arg);
int sys_process_policy(int scope, int action, int policy, int policy_subtype,
		user_addr_t attrp, uint64_t target_pid,
		uint64_t target_threadid);
int sys_mlockall(int how);
int sys_munlockall(int how);
int sys_issetugid(void);
int sys___pthread_kill(int thread_port, int sig);
int sys___pthread_sigmask(int how, user_addr_t set, user_addr_t oset);
int sys___sigwait(user_addr_t set, user_addr_t sig);
int sys___disable_threadsignal(int value);
int sys___pthread_markcancel(int thread_port);
int sys___pthread_canceled(int action);
int sys___semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative,
		int64_t tv_sec, int32_t tv_nsec);
int sys_proc_info(int32_t callnum, int32_t pid, uint32_t flavor, uint64_t arg,
		user_addr_t buffer, int32_t buffersize);
int sys_sendfile(int fd, int s, off_t offset, off_t *nbytes, void *hdtr,
		int flags);
int sys_stat64(user_addr_t path, user_addr_t ub);
int sys_sys_fstat64(int fd, user_addr_t ub);
int sys_lstat64(user_addr_t path, user_addr_t ub);
int sys_stat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size);
int sys_lstat64_extended(user_addr_t path, user_addr_t ub,
		user_addr_t xsecurity, user_addr_t xsecurity_size);
int sys_sys_fstat64_extended(int fd, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size);
user_ssize_t sys_getdirentries64(
		int fd, void *buf, user_size_t bufsize, off_t *position);
int sys_statfs64(char *path, void *buf);
int sys_fstatfs64(int fd, void *buf);
int sys_getfsstat64(user_addr_t buf, int bufsize, int flags);
int sys___pthread_chdir(user_addr_t path);
int sys___pthread_fchdir(int fd);
int sys_audit(void *record, int length);
int sys_auditon(int cmd, void *data, int length);
int sys_getauid(void *auid);
int sys_setauid(void *auid);
int sys_getaudit_addr(void *auditinfo_addr, int length);
int sys_setaudit_addr(void *auditinfo_addr, int length);
int sys_auditctl(char *path);
user_addr_t sys_bsdthread_create(user_addr_t func, user_addr_t func_arg,
		user_addr_t stack, user_addr_t pthread, uint32_t flags);
int sys_bsdthread_terminate(user_addr_t stackaddr, size_t freesize,
		uint32_t port, uint32_t sem);
int sys_kqueue(void);
int sys_kevent(int fd, void *changelist, int nchanges, void *eventlist,
		int nevents, void *timeout);
int sys_lchown(user_addr_t path, void *owner, void *group);
int sys_bsdthread_register(user_addr_t threadstart, user_addr_t wqthread,
		uint32_t flags, user_addr_t stack_addr_hint,
		user_addr_t targetconc_ptr, uint32_t dispatchqueue_offset,
		uint32_t tsd_offset);
int sys_workq_open(void);
int sys_workq_kernreturn(int options, user_addr_t item, int affinity, int prio);
int sys_kevent64(int fd, void *changelist, int nchanges, void *eventlist,
		int nevents, void *flags, void *timeout);
uint64_t sys_thread_selfid(void);
int sys_ledger(int cmd, void *arg1, void *arg2, void *arg3);
int sys_kevent_qos(int fd, void *changelist, int nchanges, void *eventlist,
		int nevents, void *data_out, size_t *data_available,
		void *flags);
int sys_kevent_id(uint64_t id, void *changelist, int nchanges, void *eventlist,
		int nevents, void *data_out, size_t *data_available,
		void *flags);
int sys___mac_execve(char *fname, char **argp, char **envp, void *mac_p);
int sys___mac_syscall(char *policy, int call, user_addr_t arg);
int sys___mac_get_file(char *path_p, void *mac_p);
int sys___mac_set_file(char *path_p, void *mac_p);
int sys___mac_get_link(char *path_p, void *mac_p);
int sys___mac_set_link(char *path_p, void *mac_p);
int sys___mac_get_proc(void *mac_p);
int sys___mac_set_proc(void *mac_p);
int sys___mac_get_fd(int fd, void *mac_p);
int sys___mac_set_fd(int fd, void *mac_p);
int sys___mac_get_pid(uint64_t pid, void *mac_p);
int sys_pselect(int nd, uint32_t *in, uint32_t *ou, uint32_t *ex, void *ts,
		void *mask);
int sys___mac_mount(char *type, char *path, int flags, void *data, void *mac_p);
int sys___mac_get_mount(char *path, void *mac_p);
int sys___mac_getfsstat(user_addr_t buf, int bufsize, user_addr_t mac,
		int macsize, int flags);
user_ssize_t sys_fsgetpath(user_addr_t buf, size_t bufsize, user_addr_t fsid,
		uint64_t objid);
mach_port_name_t sys_audit_session_self(void);
int sys_audit_session_join(mach_port_name_t port);
int sys_sys_fileport_makeport(int fd, user_addr_t portnamep);
int sys_sys_fileport_makefd(mach_port_name_t port);
int sys_audit_session_port(void *asid, user_addr_t portnamep);
int sys_pid_suspend(int pid);
int sys_pid_resume(int pid);
int sys_pid_shutdown_sockets(int pid, int level);
int sys_shared_region_map_and_slide_np(int fd, uint32_t count, void *mappings,
		uint32_t slide, uint64_t *slide_start, uint32_t slide_size);
int sys_kas_info(int selector, void *value, size_t *size);
int sys_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags,
		user_addr_t buffer, size_t buffersize);
int sys_guarded_open_np(user_addr_t path, void *guard, uint32_t guardflags,
		int flags, int mode);
int sys_guarded_close_np(int fd, void *guard);
int sys_guarded_kqueue_np(void *guard, uint32_t guardflags);
int sys_change_fdguard_np(int fd, void *guard, uint32_t guardflags,
		void *nguard, uint32_t nguardflags, int *fdflagsp);
int sys_usrctl(uint32_t flags);
int sys_proc_rlimit_control(uint64_t pid, int flavor, void *arg);
int sys_connectx(int socket, void *endpoints, void *associd, void *flags,
		void *iov, void *iovcnt, size_t *len, void *connid);
int sys_disconnectx(int s, void *aid, void *cid);
int sys_peeloff(int s, void *aid);
int sys_socket_delegate(int domain, int type, int protocol, uint64_t epid);
int sys_telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval,
		uint64_t leeway, uint64_t arg4, uint64_t arg5);
int sys_proc_uuid_policy(
		uint32_t operation, void *uuid, size_t uuidlen, uint32_t flags);
int sys_memorystatus_get_level(user_addr_t level);
int sys_system_override(uint64_t timeout, uint64_t flags);
int sys_vfs_purge(void);
int sys_sfi_ctl(uint32_t operation, uint32_t sfi_class, uint64_t time,
		uint64_t *out_time);
int sys_sfi_pidctl(uint32_t operation, uint64_t pid, uint32_t sfi_flags,
		uint32_t *out_sfi_flags);
int sys_coalition(uint32_t operation, uint64_t *cid, uint32_t flags);
int sys_coalition_info(
		uint32_t flavor, uint64_t *cid, void *buffer, size_t *bufsize);
int sys_getattrlistbulk(int dirfd, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options);
int sys_clonefileat(int src_dirfd, user_addr_t src, int dst_dirfd,
		user_addr_t dst, uint32_t flags);
int sys_openat(int fd, user_addr_t path, int flags, int mode);
int sys_openat_nocancel(int fd, user_addr_t path, int flags, int mode);
int sys_renameat(int fromfd, char *from, int tofd, char *to);
int sys_faccessat(int fd, user_addr_t path, int amode, int flag);
int sys_fchmodat(int fd, user_addr_t path, int mode, int flag);
int sys_fchownat(int fd, user_addr_t path, void *uid, void *gid, int flag);
int sys_fstatat(int fd, user_addr_t path, user_addr_t ub, int flag);
int sys_fstatat64(int fd, user_addr_t path, user_addr_t ub, int flag);
int sys_linkat(int fd1, user_addr_t path, int fd2, user_addr_t link, int flag);
int sys_unlinkat(int fd, user_addr_t path, int flag);
int sys_readlinkat(int fd, user_addr_t path, user_addr_t buf, size_t bufsize);
int sys_symlinkat(user_addr_t *path1, int fd, user_addr_t path2);
int sys_mkdirat(int fd, user_addr_t path, int mode);
int sys_getattrlistat(int fd, const char *path, void *alist,
		void *attributeBuffer, size_t bufferSize, uint64_t options);
int sys_proc_trace_log(uint64_t pid, uint64_t uniqueid);
int sys_bsdthread_ctl(user_addr_t cmd, user_addr_t arg1, user_addr_t arg2,
		user_addr_t arg3);
int sys_openbyid_np(user_addr_t fsid, user_addr_t objid, int oflags);
user_ssize_t sys_recvmsg_x(int s, void *msgp, uint32_t cnt, int flags);
user_ssize_t sys_sendmsg_x(int s, void *msgp, uint32_t cnt, int flags);
uint64_t sys_thread_selfusage(void);
int sys_csrctl(uint32_t op, user_addr_t useraddr, user_addr_t usersize);
int sys_guarded_open_dprotected_np(user_addr_t path, void *guard,
		uint32_t guardflags, int flags, int dpclass, int dpflags,
		int mode);
user_ssize_t sys_guarded_write_np(
		int fd, void *guard, user_addr_t cbuf, user_size_t nbyte);
user_ssize_t sys_guarded_pwrite_np(int fd, void *guard, user_addr_t buf,
		user_size_t nbyte, off_t offset);
user_ssize_t sys_guarded_writev_np(int fd, void *guard, void *iovp, int iovcnt);
int sys_renameatx_np(
		int fromfd, char *from, int tofd, char *to, uint32_t flags);
int sys_mremap_encrypted(void *addr, size_t len, uint32_t cryptid,
		uint32_t cputype, uint32_t cpusubtype);
int sys_netagent_trigger(void *agent_uuid, size_t agent_uuidlen);
int sys_stack_snapshot_with_config(int stackshot_config_version,
		user_addr_t stackshot_config, size_t stackshot_config_size);
int sys_microstackshot(
		user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags);
int sys_persona(uint32_t operation, uint32_t flags, void *info, void *id,
		size_t *idlen, char *path);
uint64_t sys_mach_eventlink_signal(
		mach_port_name_t eventlink_port, uint64_t signal_count);
uint64_t sys_mach_eventlink_wait_until(mach_port_name_t eventlink_port,
		uint64_t wait_count, uint64_t deadline, uint32_t clock_id,
		uint32_t option);
uint64_t sys_mach_eventlink_signal_wait_until(mach_port_name_t eventlink_port,
		uint64_t wait_count, uint64_t signal_count, uint64_t deadline,
		uint32_t clock_id, uint32_t option);
int sys_work_interval_ctl(uint32_t operation, uint64_t work_interval_id,
		void *arg, size_t len);
int sys_getentropy(void *buffer, size_t size);
int sys_ulock_wait(uint32_t operation, void *addr, uint64_t value,
		uint32_t timeout);
int sys_ulock_wake(uint32_t operation, void *addr, uint64_t wake_value);
int sys_fclonefileat(
		int src_fd, int dst_dirfd, user_addr_t dst, uint32_t flags);
int sys_fs_snapshot(uint32_t op, int dirfd, user_addr_t name1,
		user_addr_t name2, user_addr_t data, uint32_t flags);
int sys_terminate_with_payload(int pid, uint32_t reason_namespace,
		uint64_t reason_code, void *payload, uint32_t payload_size,
		const char *reason_string, uint64_t reason_flags);
int __attribute__((noreturn)) sys_abort_with_payload(uint32_t reason_namespace,
		uint64_t reason_code, void *payload, uint32_t payload_size,
		const char *reason_string, uint64_t reason_flags);
int sys_setattrlistat(int fd, const char *path, void *alist,
		void *attributeBuffer, size_t bufferSize, uint32_t options);
int sys_net_qos_guideline(void *param, uint32_t param_len);
int sys_fmount(const char *type, int fd, int flags, void *data);
int sys_ntp_adjtime(void *tp);
int sys_ntp_gettime(void *ntvp);
int sys_os_fault_with_payload(uint32_t reason_namespace, uint64_t reason_code,
		void *payload, uint32_t payload_size, const char *reason_string,
		uint64_t reason_flags);
int sys_kqueue_workloop_ctl(
		user_addr_t cmd, uint64_t options, user_addr_t addr, size_t sz);
uint64_t sys___mach_bridge_remote_time(uint64_t local_timestamp);
int sys_coalition_ledger(uint32_t operation, uint64_t *cid, void *buffer,
		size_t *bufsize);
int sys_log_data(void *tag, void *flags, void *buffer, void *size);
uint64_t sys_memorystatus_available_memory(void);
int sys_shared_region_map_and_slide_2_np(uint32_t files_count, void *files,
		uint32_t mappings_count, void *mappings);
int sys_pivot_root(const char *new_rootfs_path_before,
		const char *old_rootfs_path_after);
int sys_task_inspect_for_pid(
		mach_port_name_t target_tport, int pid, mach_port_name_t *t);
int sys_task_read_for_pid(
		mach_port_name_t target_tport, int pid, mach_port_name_t *t);
user_ssize_t sys_sys_preadv(int fd, void *iovp, int iovcnt, off_t offset);
user_ssize_t sys_sys_pwritev(int fd, void *iovp, int iovcnt, off_t offset);
user_ssize_t sys_sys_preadv_nocancel(
		int fd, void *iovp, int iovcnt, off_t offset);
user_ssize_t sys_sys_pwritev_nocancel(
		int fd, void *iovp, int iovcnt, off_t offset);
int sys_ulock_wait2(uint32_t operation, void *addr, uint64_t value,
		uint64_t timeout, uint64_t value2);
int sys_proc_info_extended_id(int32_t callnum, int32_t pid, uint32_t flavor,
		uint32_t flags, uint64_t ext_id, uint64_t arg,
		user_addr_t buffer, int32_t buffersize);
