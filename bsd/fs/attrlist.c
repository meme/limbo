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

typedef uint32_t attrgroup_t;
struct __darwin_attrlist {
	uint16_t bitmapcount;
	uint16_t reserved;
	attrgroup_t commonattr;
	attrgroup_t volattr;
	attrgroup_t dirattr;
	attrgroup_t fileattr;
	attrgroup_t forkattr;
};
#define ATTR_BIT_MAP_COUNT 5

typedef struct attribute_set {
	attrgroup_t commonattr;
	attrgroup_t volattr;
	attrgroup_t dirattr;
	attrgroup_t fileattr;
	attrgroup_t forkattr;
} attribute_set_t;

typedef struct attrreference {
	int32_t attr_dataoffset;
	uint32_t attr_length;
} attrreference_t;

#define FSOPT_PACK_INVAL_ATTRS 8

#define ATTR_CMN_NAME               0x00000001
#define ATTR_CMN_DEVID              0x00000002
#define ATTR_CMN_FSID               0x00000004
#define ATTR_CMN_OBJTYPE            0x00000008
#define ATTR_CMN_OBJTAG             0x00000010
#define ATTR_CMN_OBJID              0x00000020
#define ATTR_CMN_OBJPERMANENTID     0x00000040
#define ATTR_CMN_PAROBJID           0x00000080
#define ATTR_CMN_SCRIPT             0x00000100
#define ATTR_CMN_CRTIME             0x00000200
#define ATTR_CMN_MODTIME            0x00000400
#define ATTR_CMN_CHGTIME            0x00000800
#define ATTR_CMN_ACCTIME            0x00001000
#define ATTR_CMN_BKUPTIME           0x00002000
#define ATTR_CMN_FNDRINFO           0x00004000
#define ATTR_CMN_OWNERID            0x00008000
#define ATTR_CMN_GRPID              0x00010000
#define ATTR_CMN_ACCESSMASK         0x00020000
#define ATTR_CMN_FLAGS              0x00040000
#define ATTR_CMN_GEN_COUNT          0x00080000
#define ATTR_CMN_DOCUMENT_ID        0x00100000
#define ATTR_CMN_USERACCESS         0x00200000
#define ATTR_CMN_EXTENDED_SECURITY  0x00400000
#define ATTR_CMN_UUID               0x00800000
#define ATTR_CMN_GRPUUID            0x01000000
#define ATTR_CMN_FILEID             0x02000000
#define ATTR_CMN_PARENTID           0x04000000
#define ATTR_CMN_FULLPATH           0x08000000
#define ATTR_CMN_ADDEDTIME          0x10000000
#define ATTR_CMN_ERROR              0x20000000
#define ATTR_CMN_DATA_PROTECT_FLAGS 0x40000000
#define ATTR_CMN_RETURNED_ATTRS     0x80000000
#define ATTR_CMN_VALIDMASK          0xFFFFFFFF

#define ATTR_VOL_FSTYPE          0x00000001
#define ATTR_VOL_SIGNATURE       0x00000002
#define ATTR_VOL_SIZE            0x00000004
#define ATTR_VOL_SPACEFREE       0x00000008
#define ATTR_VOL_SPACEAVAIL      0x00000010
#define ATTR_VOL_MINALLOCATION   0x00000020
#define ATTR_VOL_ALLOCATIONCLUMP 0x00000040
#define ATTR_VOL_IOBLOCKSIZE     0x00000080
#define ATTR_VOL_OBJCOUNT        0x00000100
#define ATTR_VOL_FILECOUNT       0x00000200
#define ATTR_VOL_DIRCOUNT        0x00000400
#define ATTR_VOL_MAXOBJCOUNT     0x00000800
#define ATTR_VOL_MOUNTPOINT      0x00001000
#define ATTR_VOL_NAME            0x00002000
#define ATTR_VOL_MOUNTFLAGS      0x00004000
#define ATTR_VOL_MOUNTEDDEVICE   0x00008000
#define ATTR_VOL_ENCODINGSUSED   0x00010000
#define ATTR_VOL_CAPABILITIES    0x00020000
#define ATTR_VOL_UUID            0x00040000
#define ATTR_VOL_QUOTA_SIZE      0x10000000
#define ATTR_VOL_RESERVED_SIZE   0x20000000
#define ATTR_VOL_ATTRIBUTES      0x40000000
#define ATTR_VOL_INFO            0x80000000

#define ATTR_FILE_LINKCOUNT     0x00000001
#define ATTR_FILE_TOTALSIZE     0x00000002
#define ATTR_FILE_ALLOCSIZE     0x00000004
#define ATTR_FILE_IOBLOCKSIZE   0x00000008
#define ATTR_FILE_DEVTYPE       0x00000020
#define ATTR_FILE_FORKCOUNT     0x00000080
#define ATTR_FILE_FORKLIST      0x00000100
#define ATTR_FILE_DATALENGTH    0x00000200
#define ATTR_FILE_DATAALLOCSIZE 0x00000400
#define ATTR_FILE_RSRCLENGTH    0x00001000
#define ATTR_FILE_RSRCALLOCSIZE 0x00002000

typedef uint32_t __darwin_dev_t;
typedef uint32_t fsobj_type_t;
typedef struct fsobj_id {
	uint32_t fid_objno;
	uint32_t fid_generation;
} fsobj_id_t;
enum vtype {
	VNON,
	VREG,
	VDIR,
	VBLK,
	VCHR,
	VLNK,
	VSOCK,
	VFIFO,
	VBAD,
	VSTR,
	VCPLX
};
typedef uint32_t vol_capabilities_set_t[4];

#define VOL_CAPABILITIES_FORMAT     0
#define VOL_CAPABILITIES_INTERFACES 1
#define VOL_CAPABILITIES_RESERVED1  2
#define VOL_CAPABILITIES_RESERVED2  3

typedef struct vol_capabilities_attr {
	vol_capabilities_set_t capabilities;
	vol_capabilities_set_t valid;
} vol_capabilities_attr_t;

static int
fgetattrlist(int fd, void *alist, void *attributeBuffer, size_t bufferSize,
		uint64_t options, const char *nameHint)
{
	/* Because it is non-trivial to get the path name of a file from a file
	 * descriptor on Linux, provide a hint that is passed to basename(3)
	 * for ATTR_CMN_NAME */
	if (nameHint == NULL) {
		char path[1024] = {0};
		char nameHintBuffer[1024] = {0};
		snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
		readlink(path, nameHintBuffer, sizeof(nameHintBuffer));
		nameHint = nameHintBuffer;
	}

	struct __darwin_attrlist *alistp = (struct __darwin_attrlist *)alist;
	char *buffer = (char *)attributeBuffer;
	if (alistp->bitmapcount != ATTR_BIT_MAP_COUNT) {
		errno = EINVAL;
		return 1;
	}

	if (alistp->dirattr || alistp->forkattr) {
		unimplemented();
	}

	uint32_t commonattr = alistp->commonattr;
	uint32_t volattr = alistp->volattr;
	uint32_t fileattr = alistp->fileattr;

	struct stat s = {0};
	if (fstat(fd, &s)) {
#ifdef ENABLE_STRACE
		perror("fstat");
#endif
		return 1;
	}

	/* TODO: Check bufferSize */

	/* Order must follow the definitions above, and be written to the buffer
	 * all the same */

	/* The buffer begins with a uint32_t size */
	uint32_t offset = sizeof(uint32_t);
	uint32_t name_reference_offset = 0;
	uint32_t fullname_reference_offset = 0;

	if (alistp->commonattr & ATTR_CMN_RETURNED_ATTRS) {
		attribute_set_t attr_set = {
				.commonattr = alistp->commonattr,
				.volattr = alistp->volattr,
				.dirattr = alistp->dirattr,
				.fileattr = alistp->fileattr,
				.forkattr = alistp->forkattr,
		};
		memcpy(buffer + offset, &attr_set, sizeof(attr_set));
		offset += sizeof(attr_set);
		commonattr &= ~ATTR_CMN_RETURNED_ATTRS;
	}

	if (alistp->commonattr & ATTR_CMN_NAME) {
		attrreference_t name_reference = {
				.attr_dataoffset = 0,
				.attr_length = 0,
		};
		/* Put the name after the attrreference_t */
		memcpy(buffer + offset, &name_reference,
				sizeof(name_reference));
		name_reference_offset = offset;
		offset += sizeof(name_reference);
		commonattr &= ~ATTR_CMN_NAME;
	}

	if (alistp->commonattr & ATTR_CMN_DEVID) {
		__darwin_dev_t d = s.st_dev;
		memcpy(buffer + offset, &d, sizeof(d));
		offset += sizeof(d);
		commonattr &= ~ATTR_CMN_DEVID;
	}

	if (alistp->commonattr & ATTR_CMN_OBJTYPE) {
		fsobj_type_t type = VREG;
		switch (s.st_mode & S_IFMT) {
		case S_IFBLK:
			type = VBLK;
			break;
		case S_IFCHR:
			type = VCHR;
			break;
		case S_IFDIR:
			type = VDIR;
			break;
		case S_IFIFO:
			type = VFIFO;
			break;
		case S_IFLNK:
			type = VLNK;
			break;
		case S_IFSOCK:
			type = VSOCK;
			break;
		}

		memcpy(buffer + offset, &type, sizeof(type));
		offset += sizeof(type);
		commonattr &= ~ATTR_CMN_OBJTYPE;
	}

	if (alistp->commonattr & ATTR_CMN_OBJID) {
		fsobj_id_t id = {
				.fid_objno
				= s.st_ino, /* TODO: This isn't correct */
				.fid_generation = 0xfffffff,
		};
		memcpy(buffer + offset, &id, sizeof(id));
		offset += sizeof(fsobj_id_t);
		commonattr &= ~ATTR_CMN_OBJID;
	}

	if (alistp->commonattr & ATTR_CMN_FILEID) {
		uint64_t ino = s.st_ino;
		memcpy(buffer + offset, &ino, sizeof(ino));
		offset += sizeof(uint64_t);
		commonattr &= ~ATTR_CMN_FILEID;
	}

	if (alistp->commonattr & ATTR_CMN_FULLPATH) {
		attrreference_t name_reference = {
				.attr_dataoffset = 0,
				.attr_length = 0,
		};
		/* Put the name after the attrreference_t */
		memcpy(buffer + offset, &name_reference,
				sizeof(name_reference));
		fullname_reference_offset = offset;
		offset += sizeof(name_reference);
		commonattr &= ~ATTR_CMN_FULLPATH;
	}

	if (alistp->volattr & ATTR_VOL_MOUNTFLAGS) {
		/* TODO: Return converted mount flags? */
		uint32_t flags = 0;
		memcpy(buffer + offset, &flags, sizeof(flags));
		offset += sizeof(flags);
		volattr &= ~ATTR_VOL_MOUNTFLAGS;
	}

	if (alistp->volattr & ATTR_VOL_CAPABILITIES) {
		vol_capabilities_attr_t cap = {0};
		memcpy(buffer + offset, &cap, sizeof(cap));
		offset += sizeof(cap);
		volattr &= ~ATTR_VOL_CAPABILITIES;
	}

	if (alistp->volattr & ATTR_VOL_INFO) {
		/* From the man pages, it looks like this does nothing */
		volattr &= ~ATTR_VOL_INFO;
	}

	if (alistp->fileattr & ATTR_FILE_LINKCOUNT) {
		uint32_t link_count = 0;
		memcpy(buffer + offset, &link_count, sizeof(link_count));
		offset += sizeof(link_count);
		fileattr &= ~ATTR_FILE_LINKCOUNT;
	}

	/* Attribute reference goes at the end, then backpatch */
	if (alistp->commonattr & ATTR_CMN_NAME) {
		attrreference_t *reference = (attrreference_t *)(buffer
				+ name_reference_offset);
		/* Does not include the size */
		reference->attr_dataoffset = offset - name_reference_offset;
		char *path = basename(nameHint);
		reference->attr_length = strlen(path) + 1;
		memcpy(buffer + offset, path, reference->attr_length);
		offset += reference->attr_length;
	}

	if (alistp->commonattr & ATTR_CMN_FULLPATH) {
		/* TODO: This is hacky, will not work in all cases. BUGS R US */
		attrreference_t *reference = (attrreference_t *)(buffer
				+ fullname_reference_offset);
		/* Does not include the size */
		reference->attr_dataoffset = offset - fullname_reference_offset;
		reference->attr_length = strlen(nameHint) + 1;
		memcpy(buffer + offset, nameHint, reference->attr_length);
		offset += reference->attr_length;
	}

	if (commonattr) {
#ifdef ENABLE_STRACE
		fprintf(stderr,
				">> getattrlist unhandled commonattr flags: "
				"%x\n",
				commonattr);
#endif
		unimplemented();
	}

	if (volattr) {
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> getattrlist unhandled volattr flags: %x\n",
				volattr);
#endif
		unimplemented();
	}

	if (fileattr) {
#ifdef ENABLE_STRACE
		fprintf(stderr, ">> getattrlist unhandled fileattr flags: %x\n",
				fileattr);
#endif
		unimplemented();
	}

	/* Total aligned size is written to the beginning of the buffer */
	*(uint32_t *)buffer = offset + (-offset & 3);
	return 0;
}

static int
fsetattrlist(int fd, void *alist, void *attributeBuffer, size_t bufferSize,
		uint64_t options)
{
	unimplemented();
}

int
sys_getattrlistbulk(int dirfd, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getattrlistbulk(%p, %p, %p, %p, %p)\n", (void *)dirfd,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	/* To ease implementation and write getattrlistbulk in terms of
	 * getattrlist, we return only one directory entry at a time */
	DIR *dir = fdopendir(dup(dirfd));
	struct dirent *d = readdir(dir);

	/* No entries left, or an error */
	if (d == NULL) {
		closedir(dir);
		return 0;
	}

	int fd = openat(dirfd, d->d_name, O_RDONLY);
	if (fd == -1) {
#ifdef ENABLE_STRACE
		perror("openat");
#endif
		goto error;
	}

	/* TODO: Is this the right way to handle options */
	if (fgetattrlist(fd, alist, attributeBuffer, bufferSize, options,
			    d->d_name)) {
#ifdef ENABLE_STRACE
		perror("fgetattrlist");
#endif
		goto error;
	}

	close(fd);
	/* Restore directory position */
	seekdir(dir, telldir(dir));
	closedir(dir);
	return 1;
error:
	close(fd);
	closedir(dir);
	return 0;
}

int
sys_getattrlist(const char *path, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getattrlist(\"%s\", %p, %p, %p, %p)\n", path,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
#ifdef ENABLE_STRACE
		perror("open");
#endif
		return err_map(errno);
	}

	if (fgetattrlist(fd, alist, attributeBuffer, bufferSize, options,
			    path)) {
		close(fd);
		return err_map(errno);
	}

	close(fd);
	return 0;
}

int
sys_setattrlist(const char *path, void *alist, void *attributeBuffer,
		size_t bufferSize, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setattrlist(%p, %p, %p, %p, %p)\n", (void *)path,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
#ifdef ENABLE_STRACE
		perror("open");
#endif
		return err_map(errno);
	}

	if (fsetattrlist(fd, alist, attributeBuffer, bufferSize, options)) {
		close(fd);
		return err_map(errno);
	}

	close(fd);
	return 0;
}

int
sys_fgetattrlist(int fd, void *alist, void *attributeBuffer, size_t bufferSize,
		uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fgetattrlist(%p, %p, %p, %p, %p)\n", (void *)fd,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	if (fgetattrlist(fd, alist, attributeBuffer, bufferSize, options,
			    NULL)) {
		return err_map(errno);
	}

	return 0;
}

int
sys_fsetattrlist(int fd, void *alist, void *attributeBuffer, size_t bufferSize,
		uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "fsetattrlist(%p, %p, %p, %p, %p)\n", (void *)fd,
			(void *)alist, (void *)attributeBuffer,
			(void *)bufferSize, (void *)options);
#endif
	if (fsetattrlist(fd, alist, attributeBuffer, bufferSize, options)) {
		return err_map(errno);
	}

	return 0;
}

int
sys_getattrlistat(int dirfd, const char *path, void *alist,
		void *attributeBuffer, size_t bufferSize, uint64_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "getattrlistat(%p, %p, %p, %p, %p, %p)\n",
			(void *)dirfd, (void *)path, (void *)alist,
			(void *)attributeBuffer, (void *)bufferSize,
			(void *)options);
#endif
	int fd = openat(dirfd, path, O_RDONLY);
	if (fd == -1) {
#ifdef ENABLE_STRACE
		perror("open");
#endif
		return err_map(errno);
	}

	if (fgetattrlist(fd, alist, attributeBuffer, bufferSize, options,
			    path)) {
		close(dirfd);
		return err_map(errno);
	}

	close(dirfd);
	return 0;
}

int
sys_setattrlistat(int dirfd, const char *path, void *alist,
		void *attributeBuffer, size_t bufferSize, uint32_t options)
{
#ifdef ENABLE_STRACE
	fprintf(stderr, "setattrlistat(%p, %p, %p, %p, %p, %p)\n",
			(void *)dirfd, (void *)path, (void *)alist,
			(void *)attributeBuffer, (void *)bufferSize,
			(void *)options);
#endif
	int fd = openat(dirfd, path, O_RDONLY);
	if (fd == -1) {
#ifdef ENABLE_STRACE
		perror("open");
#endif
		return err_map(errno);
	}

	if (fsetattrlist(fd, alist, attributeBuffer, bufferSize, options)) {
		close(dirfd);
		return err_map(errno);
	}

	close(dirfd);
	return 0;
}
