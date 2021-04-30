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
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bsd/xnu-errno.h"

typedef size_t user_size_t;
typedef ssize_t user_ssize_t;

#define _MAXPATHLEN 1024

#define _DT_UNKNOWN 0
#define _DT_FIFO    1
#define _DT_CHR     2
#define _DT_DIR     4
#define _DT_BLK     6
#define _DT_REG     8
#define _DT_LNK     10
#define _DT_SOCK    12
#define _DT_WHT     14

struct __darwin_struct_dirent {
	uint64_t d_ino;
	uint64_t d_seekoff;
	uint16_t d_reclen;
	uint16_t d_namlen;
	uint8_t d_type;
	char d_name[_MAXPATHLEN];
};

user_ssize_t
sys_getdirentries64(int dirfd, void *buf, user_size_t bufsize, off_t *position)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getdirentries64(%p, %p, %p, %p)\n", (void *)dirfd,
			(void *)buf, (void *)bufsize, (void *)position);
#endif
	DIR *dir = fdopendir(dup(dirfd));
	if (dir == NULL) {
#ifdef ENABLE_STRACE
		perror("fdopendir");
#endif
		return 0;
	}
	struct dirent *d = readdir(dir);

	/* No entries left, or an error */
	if (d == NULL) {
		closedir(dir);
		return 0;
	}

	struct __darwin_struct_dirent ent = {
			.d_ino = d->d_ino,
			.d_seekoff = d->d_off,
			.d_reclen = sizeof(struct __darwin_struct_dirent)
					- _MAXPATHLEN + strlen(d->d_name) + 1,
			.d_namlen = strlen(d->d_name) + 1,
	};

	switch (d->d_type) {
	case DT_FIFO:
		ent.d_type = DT_FIFO;
		break;
	case DT_CHR:
		ent.d_type = _DT_CHR;
		break;
	case DT_BLK:
		ent.d_type = DT_BLK;
		break;
	case DT_REG:
		ent.d_type = _DT_REG;
		break;
	case DT_LNK:
		ent.d_type = _DT_LNK;
		break;
	case DT_SOCK:
		ent.d_type = _DT_SOCK;
		break;
	case DT_WHT:
		ent.d_type = _DT_WHT;
		break;
	case DT_UNKNOWN:
	default:
		ent.d_type = _DT_UNKNOWN;
		break;
	}

	/* TODO: Linux paths can be longer than MAXPATHLEN, should we truncate
	 */
	if (strlen(d->d_name) + 1 > _MAXPATHLEN) {
		unimplemented();
	}

	if (bufsize < ent.d_reclen) {
		return _ERANGE;
	}

	memcpy(ent.d_name, d->d_name, strlen(d->d_name) + 1);

	memcpy(buf, &ent, ent.d_reclen);

	if (position) {
		*position = lseek(dirfd, 0, SEEK_CUR);
	}

	/* Restore directory position */
	seekdir(dir, telldir(dir));
	closedir(dir);
	return sizeof(ent);
error:
	closedir(dir);
	return 0;
}

int
sys_getdirentries(int fd, char *buf, uint32_t count, long *basep)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getdirentries(%p, %p, %p, %p)\n", (void *)fd,
			(void *)buf, (void *)count, (void *)basep);
#endif
	unimplemented();
}

int
sys_getdirentriesattr(int fd, void *alist, void *buffer, size_t buffersize,
		void *count, void *basep, void *newstate, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getdirentriesattr(%p, %p, %p, %p, %p, %p, %p, %p)\n",
			(void *)fd, (void *)alist, (void *)buffer,
			(void *)buffersize, (void *)count, (void *)basep,
			(void *)newstate, (void *)options);
#endif
	unimplemented();
}
