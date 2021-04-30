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

#include <errno.h>

/* Inspired by the error translation primitives in iSH and libc-shim */

#define _EPERM           -1
#define _ENOENT          -2
#define _ESRCH           -3
#define _EINTR           -4
#define _EIO             -5
#define _ENXIO           -6
#define _E2BIG           -7
#define _ENOEXEC         -8
#define _EBADF           -9
#define _ECHILD          -10
#define _EDEADLK         -11
#define _ENOMEM          -12
#define _EACCES          -13
#define _EFAULT          -14
#define _ENOTBLK         -15
#define _EBUSY           -16
#define _EEXIST          -17
#define _EXDEV           -18
#define _ENODEV          -19
#define _ENOTDIR         -20
#define _EISDIR          -21
#define _EINVAL          -22
#define _ENFILE          -23
#define _EMFILE          -24
#define _ENOTTY          -25
#define _ETXTBSY         -26
#define _EFBIG           -27
#define _ENOSPC          -28
#define _ESPIPE          -29
#define _EROFS           -30
#define _EMLINK          -31
#define _EPIPE           -32
#define _EDOM            -33
#define _ERANGE          -34
#define _EAGAIN          -35
#define _EWOULDBLOCK     _EAGAIN
#define _EINPROGRESS     -36
#define _EALREADY        -37
#define _ENOTSOCK        -38
#define _EDESTADDRREQ    -39
#define _EMSGSIZE        -40
#define _EPROTOTYPE      -41
#define _ENOPROTOOPT     -42
#define _EPROTONOSUPPORT -43
#define _ESOCKTNOSUPPORT -44
#define _ENOTSUP         -45
#define _EPFNOSUPPORT    -46
#define _EAFNOSUPPORT    -47
#define _EADDRINUSE      -48
#define _EADDRNOTAVAIL   -49
#define _ENETDOWN        -50
#define _ENETUNREACH     -51
#define _ENETRESET       -52
#define _ECONNABORTED    -53
#define _ECONNRESET      -54
#define _ENOBUFS         -55
#define _EISCONN         -56
#define _ENOTCONN        -57
#define _ESHUTDOWN       -58
#define _ETOOMANYREFS    -59
#define _ETIMEDOUT       -60
#define _ECONNREFUSED    -61
#define _ELOOP           -62
#define _ENAMETOOLONG    -63
#define _EHOSTDOWN       -64
#define _EHOSTUNREACH    -65
#define _ENOTEMPTY       -66
#define _EPROCLIM        -67
#define _EUSERS          -68
#define _EDQUOT          -69
#define _ESTALE          -70
#define _EREMOTE         -71
#define _EBADRPC         -72
#define _ERPCMISMATCH    -73
#define _EPROGUNAVAIL    -74
#define _EPROGMISMATCH   -75
#define _EPROCUNAVAIL    -76
#define _ENOLCK          -77
#define _ENOSYS          -78
#define _EFTYPE          -79
#define _EAUTH           -80
#define _ENEEDAUTH       -81
#define _EPWROFF         -82
#define _EDEVERR         -83
#define _EOVERFLOW       -84
#define _EBADEXEC        -85
#define _EBADARCH        -86
#define _ESHLIBVERS      -87
#define _EBADMACHO       -88
#define _ECANCELED       -89
#define _EIDRM           -90
#define _ENOMSG          -91
#define _EILSEQ          -92
#define _ENOATTR         -93
#define _EBADMSG         -94
#define _EMULTIHOP       -95
#define _ENODATA         -96
#define _ENOLINK         -97
#define _ENOSR           -98
#define _ENOSTR          -99
#define _EPROTO          -100
#define _ETIME           -101
#define _EOPNOTSUPP      -102
#define _ENOPOLICY       -103
#define _ENOTRECOVERABLE -104
#define _EOWNERDEAD      -105
#define _EQFULL          -106
#define _ELAST           -106

static inline int
err_map(int err)
{
	/* TODO: Decide the fate of missing Darwin error codes */
	if (err >= 0) {
		return err;
	}

	switch (err) {
	case EPERM:
		return _EPERM;
	case ENOENT:
		return _ENOENT;
	case ESRCH:
		return _ESRCH;
	case EINTR:
		return _EINTR;
	case EIO:
		return _EIO;
	case ENXIO:
		return _ENXIO;
	case ENOEXEC:
		return _ENOEXEC;
	case EBADF:
		return _EBADF;
	case ECHILD:
		return _ECHILD;
	case EDEADLK:
		return _EDEADLK;
	case ENOMEM:
		return _ENOMEM;
	case EACCES:
		return _EACCES;
	case EFAULT:
		return _EFAULT;
	case ENOTBLK:
		return _ENOTBLK;
	case EBUSY:
		return _EBUSY;
	case EEXIST:
		return _EEXIST;
	case EXDEV:
		return _EXDEV;
	case ENODEV:
		return _ENODEV;
	case ENOTDIR:
		return _ENOTDIR;
	case EISDIR:
		return _EISDIR;
	case EINVAL:
		return _EINVAL;
	case ENFILE:
		return _ENFILE;
	case EMFILE:
		return _EMFILE;
	case ENOTTY:
		return _ENOTTY;
	case ETXTBSY:
		return _ETXTBSY;
	case EFBIG:
		return _EFBIG;
	case ENOSPC:
		return _ENOSPC;
	case ESPIPE:
		return _ESPIPE;
	case EROFS:
		return _EROFS;
	case EMLINK:
		return _EMLINK;
	case EPIPE:
		return _EPIPE;
	case EDOM:
		return _EDOM;
	case ERANGE:
		return _ERANGE;
	case EAGAIN:
		return _EAGAIN;
	case EINPROGRESS:
		return _EINPROGRESS;
	case EALREADY:
		return _EALREADY;
	case ENOTSOCK:
		return _ENOTSOCK;
	case EDESTADDRREQ:
		return _EDESTADDRREQ;
	case EMSGSIZE:
		return _EMSGSIZE;
	case EPROTOTYPE:
		return _EPROTOTYPE;
	case ENOPROTOOPT:
		return _ENOPROTOOPT;
	case EPROTONOSUPPORT:
		return _EPROTONOSUPPORT;
	case ESOCKTNOSUPPORT:
		return _ESOCKTNOSUPPORT;
	/* case ENOTSUP: return _ENOTSUP; */
	case EPFNOSUPPORT:
		return _EPFNOSUPPORT;
	case EAFNOSUPPORT:
		return _EAFNOSUPPORT;
	case EADDRINUSE:
		return _EADDRINUSE;
	case EADDRNOTAVAIL:
		return _EADDRNOTAVAIL;
	case ENETDOWN:
		return _ENETDOWN;
	case ENETUNREACH:
		return _ENETUNREACH;
	case ENETRESET:
		return _ENETRESET;
	case ECONNABORTED:
		return _ECONNABORTED;
	case ECONNRESET:
		return _ECONNRESET;
	case ENOBUFS:
		return _ENOBUFS;
	case EISCONN:
		return _EISCONN;
	case ENOTCONN:
		return _ENOTCONN;
	case ESHUTDOWN:
		return _ESHUTDOWN;
	case ETOOMANYREFS:
		return _ETOOMANYREFS;
	case ETIMEDOUT:
		return _ETIMEDOUT;
	case ECONNREFUSED:
		return _ECONNREFUSED;
	case ELOOP:
		return _ELOOP;
	case ENAMETOOLONG:
		return _ENAMETOOLONG;
	case EHOSTDOWN:
		return _EHOSTDOWN;
	case EHOSTUNREACH:
		return _EHOSTUNREACH;
	case ENOTEMPTY:
		return _ENOTEMPTY;
	/* case EPROCLIM: return _EPROCLIM; */
	case EUSERS:
		return _EUSERS;
	case EDQUOT:
		return _EDQUOT;
	case ESTALE:
		return _ESTALE;
	case EREMOTE:
		return _EREMOTE;
	/* case EBADRPC: return _EBADRPC; */
	/* case ERPCMISMATCH: return _ERPCMISMATCH; */
	/* case EPROGUNAVAIL: return _EPROGUNAVAIL; */
	/* case EPROGMISMATCH: return _EPROGMISMATCH; */
	/* case EPROCUNAVAIL: return _EPROCUNAVAIL; */
	case ENOLCK:
		return _ENOLCK;
	case ENOSYS:
		return _ENOSYS;
		/*  case EFTYPE: return _EFTYPE; */;
		/*  case EAUTH: return _EAUTH; */;
	/* case ENEEDAUTH: return _ENEEDAUTH; */
	/* case EPWROFF: return _EPWROFF; */
	/* case EDEVERR: return _EDEVERR; */
	case EOVERFLOW:
		return _EOVERFLOW;
	case ELIBBAD:
		return _EBADEXEC;
	/* case EBADARCH: return _EBADARCH; */
	/* case ESHLIBVERS: return _ESHLIBVERS; */
	/* case EBADMACHO: return _EBADMACHO; */
	case ECANCELED:
		return _ECANCELED;
	case EIDRM:
		return _EIDRM;
	case ENOMSG:
		return _ENOMSG;
	case EILSEQ:
		return _EILSEQ;
	/* case ENOATTR: return _ENOATTR; */
	case EBADMSG:
		return _EBADMSG;
	case EMULTIHOP:
		return _EMULTIHOP;
	case ENODATA:
		return _ENODATA;
	case ENOLINK:
		return _ENOLINK;
	case ENOSR:
		return _ENOSR;
	case ENOSTR:
		return _ENOSTR;
	case EPROTO:
		return _EPROTO;
	case ETIME:
		return _ETIME;
	case EOPNOTSUPP:
		return _EOPNOTSUPP;
	/* case ENOPOLICY:
		return _ENOPOLICY; */
	case ENOTRECOVERABLE:
		return _ENOTRECOVERABLE;
	case EOWNERDEAD:
		return _EOWNERDEAD;
	/* case EQFULL: return _EQFULL; */
	default:
		unimplemented();
	}
}

static inline int
errno_map(int r)
{
	if (r < 0) {
#ifdef ENABLE_STRACE
		perror("errno_map");
#endif
		return err_map(errno);
	}
	return r;
}
