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
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "bsd/xnu-errno.h"

typedef void *user_addr_t;

typedef int32_t __darwin_dev_t;
typedef uint16_t __darwin_mode_t;
typedef uint16_t __darwin_nlink_t;
typedef uint32_t __darwin_uid_t;
typedef uint32_t __darwin_gid_t;
typedef uint64_t __darwin_ino64_t;
typedef int32_t __darwin_blksize_t;
typedef int64_t __darwin_blkcnt_t;
typedef int64_t __darwin_off_t;

typedef int64_t __darwin_user64_time_t __attribute__((aligned(8)));

struct __darwin_user64_timespec {
	__darwin_user64_time_t tv_sec;
	__darwin_user64_time_t tv_nsec;
};

struct __darwin_user64_stat64 {
	__darwin_dev_t st_dev;
	__darwin_mode_t st_mode;
	__darwin_nlink_t st_nlink;
	__darwin_ino64_t st_ino;
	__darwin_uid_t st_uid;
	__darwin_gid_t st_gid;
	__darwin_dev_t st_rdev;
	struct __darwin_user64_timespec st_atimespec;
	struct __darwin_user64_timespec st_mtimespec;
	struct __darwin_user64_timespec st_ctimespec;
	struct __darwin_user64_timespec st_birthtimespec;
	__darwin_off_t st_size;
	__darwin_blkcnt_t st_blocks;
	__darwin_blksize_t st_blksize;
	uint32_t st_flags;
	uint32_t st_gen;
	uint32_t st_lspare;
	int64_t st_qspare[2];
};

#define MFSNAMELEN     15
#define MFSTYPENAMELEN 16

#define MAXPATHLEN 1024
#define MNAMELEN   MAXPATHLEN

#define MNT_EXT_ROOT_DATA_VOL 0x00000001

struct __darwin_struct_statfs64 {
	uint32_t f_bsize;
	int32_t f_iosize;
	uint64_t f_blocks;
	uint64_t f_bfree;
	uint64_t f_bavail;
	uint64_t f_files;
	uint64_t f_ffree;
	fsid_t f_fsid;
	uid_t f_owner;
	uint32_t f_type;
	uint32_t f_flags;
	uint32_t f_fssubtype;
	char f_fstypename[MFSTYPENAMELEN];
	char f_mntonname[MAXPATHLEN];
	char f_mntfromname[MAXPATHLEN];
	uint32_t f_flags_ext;
	uint32_t f_reserved[7];
};

static inline void
xnu_encode_statx_timespec(struct __darwin_user64_timespec *to,
		struct statx_timestamp *from)
{
	to->tv_sec = from->tv_sec;
	to->tv_nsec = from->tv_nsec;
}

static inline void
convert_statx(struct statx *stat, struct __darwin_user64_stat64 *dest)
{
	dest->st_dev = stat->stx_dev_major;
	dest->st_mode = stat->stx_mode;
	dest->st_nlink = stat->stx_nlink;
	dest->st_ino = stat->stx_ino;
	dest->st_uid = stat->stx_uid;
	dest->st_gid = stat->stx_gid;
	dest->st_rdev = stat->stx_rdev_major;
	xnu_encode_statx_timespec(&dest->st_atimespec, &stat->stx_atime);
	xnu_encode_statx_timespec(&dest->st_mtimespec, &stat->stx_mtime);
	xnu_encode_statx_timespec(&dest->st_ctimespec, &stat->stx_ctime);
	xnu_encode_statx_timespec(&dest->st_birthtimespec, &stat->stx_btime);
	dest->st_size = stat->stx_size;
	dest->st_blocks = stat->stx_blocks;
	dest->st_blksize = stat->stx_blksize;
	dest->st_flags = 0;
	dest->st_gen = 0;
}

static inline void
convert_stat(struct stat *stat, struct __darwin_user64_stat64 *dest)
{
	/* TODO: Handle timespec, not sure how we get that from stat(2) */
	/* TODO: Why, just make this statx */

#define _S_IFMT   0170000
#define _S_IFIFO  0010000
#define _S_IFCHR  0020000
#define _S_IFDIR  0040000
#define _S_IFBLK  0060000
#define _S_IFREG  0100000
#define _S_IFLNK  0120000
#define _S_IFSOCK 0140000

	int mode;
	switch (stat->st_mode & S_IFMT) {
	case S_IFBLK:
		mode = _S_IFBLK;
		break;
	case S_IFCHR:
		mode = _S_IFCHR;
		break;
	case S_IFDIR:
		mode = _S_IFDIR;
		break;
	case S_IFIFO:
		mode = _S_IFIFO;
		break;
	case S_IFLNK:
		mode = _S_IFLNK;
		break;
	case S_IFREG:
		mode = _S_IFREG;
		break;
	case S_IFSOCK:
		mode = _S_IFSOCK;
		break;
	default:
		unimplemented();
	}

	dest->st_mode = stat->st_mode; // mode & _S_IFMT;
	dest->st_nlink = stat->st_nlink;
	dest->st_ino = stat->st_ino;
	dest->st_uid = stat->st_uid;
	dest->st_gid = stat->st_gid;
	dest->st_size = stat->st_size;
	dest->st_blocks = stat->st_blocks;
	dest->st_blksize = stat->st_blksize;
	dest->st_flags = 0;
	dest->st_gen = 0;
}

int
sys_getfsstat(user_addr_t buf, int bufsize, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getfsstat(%p, %p, %p)\n", (void *)buf, (void *)bufsize,
			(void *)flags);
#endif
	unimplemented();
}

int
sys_statfs(char *path, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "statfs(%p, %p)\n", (void *)path, (void *)buf);
#endif
	unimplemented();
}

int
sys_fstatfs(int fd, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fstatfs(%p, %p)\n", (void *)fd, (void *)buf);
#endif
	unimplemented();
}

int
sys_stat(user_addr_t path, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "stat(%p, %p)\n", (void *)path, (void *)ub);
#endif
	unimplemented();
}

int
sys_sys_fstat(int fd, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fstat(%p, %p)\n", (void *)fd, (void *)ub);
#endif
	unimplemented();
}

int
sys_lstat(user_addr_t path, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lstat(%p, %p)\n", (void *)path, (void *)ub);
#endif
	struct statx tmp;
	int status = statx(AT_FDCWD, (char *)path, AT_SYMLINK_NOFOLLOW,
			STATX_ALL, &tmp);
	if (status < 0) {
#ifdef ENABLE_STRACE
		perror("stat");
#endif
		return err_map(errno);
	}
	convert_statx(&tmp, (void *)ub);
	return status;
}

int
sys_stat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "stat_extended(%p, %p, %p, %p)\n", (void *)path,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	unimplemented();
}

int
sys_lstat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lstat_extended(%p, %p, %p, %p)\n", (void *)path,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	unimplemented();
}

int
sys_sys_fstat_extended(int fd, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fstat_extended(%p, %p, %p, %p)\n", (void *)fd,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	unimplemented();
}

int
sys_stat64(user_addr_t path, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "stat64(\"%s\", %p)\n", (char *)path, (void *)ub);
#endif
	struct statx tmp;
	int status = statx(AT_FDCWD, (char *)path, 0, STATX_ALL, &tmp);
	if (status < 0) {
#ifdef ENABLE_STRACE
		perror("stat");
#endif
		return err_map(errno);
	}
	convert_statx(&tmp, (void *)ub);
	return status;
}

int
sys_sys_fstat64(int fd, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fstat64(%p, %p)\n", (void *)fd, (void *)ub);
#endif
	struct stat tmp = {0};
	int status = fstat(fd, &tmp);
	if (status < 0) {
#ifdef ENABLE_STRACE
		perror("stat");
#endif
		return err_map(errno);
	}
	convert_stat(&tmp, (void *)ub);
	return status;
}

int
sys_lstat64(user_addr_t path, user_addr_t ub)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lstat64(\"%s\", %p)\n", (char *)path, (void *)ub);
#endif
	struct statx tmp;
	int status = statx(AT_FDCWD, (char *)path, AT_SYMLINK_NOFOLLOW,
			STATX_ALL, &tmp);
	if (status < 0) {
#ifdef ENABLE_STRACE
		perror("stat");
#endif
		return err_map(errno);
	}
	convert_statx(&tmp, (void *)ub);
	return status;
}

int
sys_stat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "stat64_extended(%p, %p, %p, %p)\n", (void *)path,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	unimplemented();
}

int
sys_lstat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "lstat64_extended(%p, %p, %p, %p)\n", (void *)path,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	unimplemented();
}

int
sys_sys_fstat64_extended(int fd, user_addr_t ub, user_addr_t xsecurity,
		user_addr_t xsecurity_size)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "sys_fstat64_extended(%p, %p, %p, %p)\n", (void *)fd,
			(void *)ub, (void *)xsecurity, (void *)xsecurity_size);
#endif
	unimplemented();
}

int
sys_statfs64(char *path, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "statfs64(\"%s\", %p)\n", path, (void *)buf);
#endif
	struct statfs tmp = {0};
	if (statfs(path, &tmp) == -1) {
#ifdef ENABLE_STRACE
		perror("statfs");
#endif
		return err_map(errno);
	}
	struct __darwin_struct_statfs64 *statfs
			= (struct __darwin_struct_statfs64 *)buf;
	memset(statfs, 0, sizeof(*statfs));
	/* Technically this is f_iosize and distinct from f_bsize, but it is
	 * correct enough */
	statfs->f_bsize = tmp.f_bsize;
	statfs->f_iosize = tmp.f_bsize;
	statfs->f_blocks = tmp.f_blocks;
	statfs->f_bfree = tmp.f_bfree;
	statfs->f_bavail = tmp.f_bavail;
	statfs->f_files = tmp.f_files;
	statfs->f_ffree = tmp.f_ffree;
	/* TODO: These are not going to be compatible */
	statfs->f_fsid = tmp.f_fsid;
	statfs->f_type = tmp.f_type;
	/* This makes dyld use getdirentries64, but I am not sure what it does,
	 * it checks if the 0x20 bit is set */
	statfs->f_flags = 0x20;
	/* statfs->f_owner = tmp.f_owner; */
	/* statfs->f_fssubtype = tmp.f_fssubtype; */
	return 0;
}

int
sys_fstatfs64(int fd, void *buf)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fstatfs64(%p, %p)\n", (void *)fd, (void *)buf);
#endif
	struct statfs tmp = {0};
	if (fstatfs(fd, &tmp) == -1) {
#ifdef ENABLE_STRACE
		perror("fstatfs");
#endif
		return err_map(errno);
	}
	struct __darwin_struct_statfs64 *statfs
			= (struct __darwin_struct_statfs64 *)buf;
	memset(statfs, 0, sizeof(*statfs));
	/* Technically this is f_iosize and distinct from f_bsize, but it is
	 * correct enough */
	statfs->f_bsize = tmp.f_bsize;
	statfs->f_iosize = tmp.f_bsize;
	statfs->f_blocks = tmp.f_blocks;
	statfs->f_bfree = tmp.f_bfree;
	statfs->f_bavail = tmp.f_bavail;
	statfs->f_files = tmp.f_files;
	statfs->f_ffree = tmp.f_ffree;
	/* TODO: These are not going to be compatible */
	statfs->f_fsid = tmp.f_fsid;
	statfs->f_type = tmp.f_type;
	/* This makes dyld use getdirentries64, but I am not sure what it does,
	 * it checks if the 0x20 bit is set */
	statfs->f_flags = 0x20;
	/* statfs->f_owner = tmp.f_owner; */
	/* statfs->f_fssubtype = tmp.f_fssubtype; */
	return 0;
}

int
sys_getfsstat64(user_addr_t buf, int bufsize, int flags)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getfsstat64(%p, %p, %p)\n", (void *)buf,
			(void *)bufsize, (void *)flags);
#endif
	unimplemented();
}

int
sys_fstatat(int fd, user_addr_t path, user_addr_t ub, int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fstatat(%p, %p, %p, %p)\n", (void *)fd, (void *)path,
			(void *)ub, (void *)flag);
#endif
	unimplemented();
}

#define xnu_AT_FDCWD -2

int
sys_fstatat64(int fd, user_addr_t path, user_addr_t ub, int flag)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fstatat64(%p, %p, %p, %p)\n", (void *)fd, (void *)path,
			(void *)ub, (void *)flag);
#endif
	if (fd == xnu_AT_FDCWD && flag == 0) {
		struct statx tmp;
		int status = statx(AT_FDCWD, (char *)path, 0, STATX_ALL, &tmp);
		if (status < 0) {
#ifdef ENABLE_STRACE
			perror("stat");
#endif
			return err_map(errno);
		}
		convert_statx(&tmp, (void *)ub);
		return status;
	}

	unimplemented();
}
