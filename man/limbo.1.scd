limbo(1)

# NAME

limbo - XNU in Linux userspace

# SYNOPSIS

_limbo_ [path]

This program is not meant to be executed directly. Instead, register binfmt handlers
for Mach-O programs.

# DESCRIPTION

Limbo is an XNU emulator similar to qemu-user; it translates XNU system calls
into their Linux equivalent(s). It is capable of executing supported binaries
targeting macOS or iOS on Linux without modification.

# OPTIONS

*path*
	Executes the specified file in Limbo.

# SEE ALSO

*cache-lookup*(1)

# AUTHORS

Maintained by Keegan Saunders <keegan@undefinedbehaviour.org>, who is assisted
by other open source contributors. For more information about Limbo development,
see https://github.com/ksaunders/limbo.
