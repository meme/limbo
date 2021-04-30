bsd_lib = static_library('bsd',
  sources: [
    'handler.c',
    'csr.c',
    'mac.c',
    'sysctl.c',
    'fs/stat.c',
    'fs/attrlist.c',
    'fs/fcntl.c',
    'fs/getdirentries.c',
  ],
  include_directories: include_dir,
  c_args: [
    '-Wno-packed-not-aligned',
    '-Wno-unused-parameter',
    '-Wno-pedantic',
    '-Wno-int-to-pointer-cast',
  ],
)
