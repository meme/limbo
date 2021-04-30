subdir('bootstrap')

osfmk_lib = static_library('osfmk',
  sources: [
    'handler.c',
    'mach_host.c',
    'mach_hostServer.c',
    'task.c',
    'taskServer.c',
  ],
  include_directories: include_dir,
  c_args: [
    '-Wno-packed-not-aligned',
    '-Wno-unused-parameter',
    '-Wno-pedantic',
    '-Wno-int-to-pointer-cast',
  ],
  link_with: [bootstrap_lib],
)
