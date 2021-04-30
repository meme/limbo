# Contributing to Limbo

To have your code considered for inclusion, send a pull request.

To discuss the development of Limbo, visit [#limbo](https://webirc.oftc.net:8443/?channels=limbo)
on [irc.oftc.net](https://www.oftc.net/).

## Commit Messages

This codebases follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).
Due to the nature of Limbo, there are no stability guarantees so stating breaking
changes is not necessary.

## Code Style

Limbo code is provided with a `.clang-format` and `.editorconfig` file. The
codebase is formatted with `clang-format -i` such that any given patch must not
have any changes after running `clang-format`. The format is meant to match Drew
DeVault's [cstyle](https://git.sr.ht/~sircmpwn/cstyle) as closely as possible,
but due to limitations of `clang-format` it may not be 100% correct. In any case,
`clang-format` is the single source of truth.

All files must be named in `snake_case` unless they are executables, such as
`cache-lookup` or their associated man page: `cache-lookup.1`.

The order of definitions in a file should follow [cstyle](https://git.sr.ht/~sircmpwn/cstyle),
except for functions definitions which follow a newspaper article-like format.
The core of the file should be the first function definition and all the helper
subroutines should be placed after. In other terms, the order of functions should
loosely follow the flattened call graph of the first function definition.

## Development

Limbo requires a *chroot*(1) and *binfmt.d*(5) configured which can be tricky to
get right. This is not the only way, and may not be the best way, but is how
Limbo developers have set up their development environments:

* In the root of the repository, create a `mnt` folder which contains your
  bootstrapped macOS chroot
* Create the `mnt/build` folder and bind mount your `build` folder into it: `sudo mount --bind build mnt/build`
* Modify `/etc/binfmt.d/Mach-O.conf` to point it at your `limbo` and remove the `F` flag,
  (see [binfmt-misc.rst](https://www.kernel.org/doc/html/latest/admin-guide/binfmt-misc.html))
  then re-install the configuration with `systemctl restart systemd-binfmt` if using *systemd*(1)
* Mount `proc`, `sys` and `dev` into `mnt`:
  ```
  # cd mnt && mkdir -p proc sys dev
  # mount -t proc /proc proc/
  # mount --rbind /sys sys/
  # mount --rbind /dev dev/
  ```

Now, run `meson build -Dstrace=enabled` and `ninja -C build` to build a `limbo` binary
with system call tracing enabled. Then test your chroot:
`sudo chroot mnt /bin/echo Hello, world` which should print "Hello, world".
Try making a change to `limbo`, like adding a `puts` in `main()`, and ensure
the change is reflected.

Read on for details on how to debug your changes.

## Debugging

To debug Limbo, build or acquire a **static** `gdbserver` from your package manager and place
it in your chroot. Then, run `gdbserver` and pass it the path to your program:

```
sudo -E chroot mnt /gdbserver --no-startup-with-shell 127.0.0.1:1337 /bin/echo
```

Now you should be able to debug, but there a few other modifications that
make it a more pleasant experience. Add these to your `~/.gdbinit`:

```
set disassembly-flavor intel
set auto-load safe-path /a/path/limbo
set auto-load local-gdbinit on
```

This will automatically load the `.gdbinit` in the root of this repository which
will automatically connect to the `gdbserver` program and step over `SIGSYS`.
