cache-lookup(1)

# NAME

cache-lookup - Perform dyld cache lookup operations

# SYNOPSIS

_cache-lookup_ [address] [path]

This tool is useful for debugging *gdb*(1) backtraces that contain frames inside
of the dyld cache. The dyld cache images are enumerated and compared against
the provided address to determine the name of the dylib that contains the code
corresponding to it. In most circumstances, it will also print the offset into
the function containing the address as well, to ease disassembly.

# OPTIONS

*address*
	The address to search for in the executable section of dyld cache entries.

*path*
	The location of the dyld cache on disk.

# SEE ALSO

*limbo*(1)

# AUTHORS

Maintained by Keegan Saunders <keegan@undefinedbehaviour.org>, who is assisted
by other open source contributors. For more information about Limbo development,
see https://github.com/ksaunders/limbo.
