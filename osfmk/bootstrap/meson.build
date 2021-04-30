bootstrap_lib = static_library('bootstrap',
  sources: [
    'bootstrap.c',
    'bootstrapServer.c',
  ],
  include_directories: include_dir,
  c_args: [
    '-Wno-packed-not-aligned',
    '-Wno-unused-parameter',
    '-Wno-pedantic',
    '-Wno-uninitialized',
    '-Wno-unused-local-typedefs',
    '-Wno-attributes',
  ],
)
