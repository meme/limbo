# limbo

Limbo is an XNU emulator similar to qemu-user; it translates XNU system calls
into their Linux equivalent(s). It is capable of executing supported binaries
targeting macOS or iOS on Linux without modification.

Limbo is currently only supported on Linux 5.11 or later with the
`CONFIG_GENERIC_ENTRY` option enabled. This is required to capture system calls
made by the guest program.

Sufficiently advanced programs, such as Apple Clang, are capable of compiling
binaries which can also be run in Limbo.

## Installation

Before installing, read the BSD-2-Clause [license](LICENSE).

To install, ensure [Meson](https://mesonbuild.com/) is installed and run the
following commands:
```
meson build
ninja -C build install
```

This will install Limbo and the associated documentation, but you must install
the *binfmt.d*(5) handlers by copying `etc/binfmt.d/Mach-O.conf` to
`/etc/binfmt.d/Mach-O.conf`. For development, omit the `install` option and
review [CONTRIBUTING.md](CONTRIBUTING.md). The [Development](CONTRIBUTING.md#Development)
section describes how to set up a development environment. The [Internals](#Internals)
section of the README gives an overview of how Limbo works.

## User's Guide

Limbo relies on a userspace like macOS or iOS to operate, so your chroot must be
populated, or "bootstrapped", before use. There are a number of options available
depending on your use-case. All examples assume that there is an empty folder at
`$CHROOT`, the target chroot.

It does not matter what architecture your bootstrapping Mac is, because Big Sur
ships most utilities as Fat Mach-O binaries. However, non-Fat Mach-O binaries
are also supported by Limbo, but must match your architecture.

### Minimalist

For simple binaries like `echo`, only the dyld cache and dyld itself is required.
Thus on a Big Sur Mac, using `scp` or `rsync`, copy `dyld_shared_cache_x86_64`
into your chroot:

On the Limbo host:
```
mkdir -p $CHROOT/System/Library/dyld $CHROOT/bin $CHROOT/usr/lib
```

On the Big Sur Mac:
```
scp /System/Library/dyld/dyld_shared_cache_x86_64 $HOST:$CHROOT/System/Library/dyld/dyld_shared_cache_x86_64
scp /usr/lib/dyld $HOST:$CHROOT/usr/lib/dyld
scp $(which echo) $HOST:$CHROOT/bin/echo
```

Then run the program on the Limbo host:
```
sudo chroot $CHROOT /bin/echo Hello, world
```

Which should print "Hello, world".

### Xcode

Xcode command-line tools are a work-in-progress, but you will find that most tools
like `clang` or `ld64` work as expected in their basic configuration if invoked
_without_ `xcrun` (though `xcrun` itself does work, `xcodebuild` does not, yet).

First follow the [Minimalist](#Minimalist) guide.

Ensure `Xcode.app` is installed, then copy it into the chroot with `rsync`
(must be installed on the Limbo host as well). Xcode is large so this may take
some time.

```
scp $(which file) $HOST:$CHROOT/bin/file
rsync -Pav /Applications/Xcode.app $HOST:$CHROOT/Applications
```

Set your Xcode location for `xcrun`:
```
cd $CHROOT
mkdir -p var/db
ln -s /Applications/Xcode.app/Contents/Developer/ var/db/xcode_select_link
```

Then, compile a C file and check its format with `file`:
```
echo "int main() { return 0; }" > $CHROOT/example.c
sudo chroot $CHROOT /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang -c example.c -o example.o
sudo chroot $CHROOT /bin/file example.o
```

## Internals

Limbo at its core is fundamentally simple, the complexity comes from the incongruity
between Linux and the XNU kernel.

When an application is spawned by the kernel and it detects Mach-O magic, it spawns
Limbo to "wrap" the executable by passing the path to the target program as an argument
to Limbo.

The first thing Limbo does is parse its own ELF header and enumerates the executable
segments to notify the kernel of the memory regions that are _allowed_ to perform
system calls using a Linux 5.11 feature known as Syscall User Dispatch. Any
system calls that occur outside of this region result in a `SIGSYS`. Limbo then
sets a `SIGSYS` handler as the entry point into the XNU emulation routine.

Next, Limbo loads the dyld shared cache and rebases it to the load address.
However, on Linux, the stack address actually collides with the default load
address of the dyld cache, so Limbo remaps its own stack  out of the way in a
two-stage setup process. As well, the `[vdso]` and `[vvar]` special mappings also
overlap, so they are simply unmapped (though this introduces some complications
and reduces the glibc wrappers Limbo can call).

Limbo then parses the Mach-O file and reads the load commands to look for the
`LC_LOAD_DYLINKER` which specifies the program invoked by the kernel to link the
target application. Then, that program is mapped into memory, the stack is set
up, and Limbo executes the entry point of `dyld`.

Once `dyld` is started, it takes over the process and Limbo code is only entered
when a system call is made.

The XNU kernel is a hybrid kernel with a BSD and Mach subsystem, which is reflected
in Limbo's structure: `bsd`, `osfmk` (Mach) and `mdep` (Machine-dependent). When
Limbo is interrupted, it determines the subsystem of the syscall and dispatches
it into its appropriate handler, the subsystem then determines which syscall was
executed and dispatches it again where it is handled.

---

Special thanks to [David Weinstein](https://twitter.com/insitusec) for suggesting
the name Limbo.
