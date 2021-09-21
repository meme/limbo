project('limbo', 'c',
  license: 'BSD-2-Clause',
  version: '0.1.0',
  default_options: ['warning_level=3', 'c_std=gnu11'],
)

cc = meson.get_compiler('c')
assert(cc.has_header('sys/prctl.h'), 'sys/prctl.h could not be found. Did you install the libc development package?')
assert(cc.has_header_symbol('sys/prctl.h', 'PR_SET_SYSCALL_USER_DISPATCH'), 'PR_SET_SYSCALL_USER_DISPATCH is not defined. Make sure you are using Linux 5.11 or later.')

config = configuration_data()

strace = not get_option('strace').disabled()
if strace
  config.set('ENABLE_STRACE', 1)
endif

configure_file(
  input: 'config.h.in',
  output: 'config.h',
  configuration: config,
)

add_project_arguments(
  '-include', 'config.h',
  language: 'c',
)

include_dir = [
  include_directories('include'),
  include_directories('.'),
]

shm_dep = cc.find_library('rt')
thread_dep = dependency('threads')

subdir('bsd')
subdir('mdep')
subdir('osfmk')

executable('limbo',
  sources: [
    'linker.c',
    'main.c',
    'shared_cache.c'
  ],
  include_directories: include_dir,
  dependencies: [shm_dep, thread_dep],
  link_with: [bsd_lib, mdep_lib, osfmk_lib],
  c_args: [
    '-Wno-packed-not-aligned',
    '-Wno-unused-parameter',
    '-Wno-pedantic',
  ],
  link_args: [
    '-static'
  ],
  install: true,
)

scdoc = find_program('scdoc', native: true, required: false)

if scdoc.found()
  sh = find_program('sh', native: true)
  mandir = get_option('mandir')

  pages = [
    'cache-lookup.1.scd',
    'limbo.1.scd',
  ]

  foreach page : pages
    topic = page.split('.')[0]
    section = page.split('.')[1]
    output = '@0@.@1@'.format(topic, section)

    custom_target(
      output,
      input: join_paths('man', page),
      output: output,
      command: [
        sh, '-c', '@0@ < @INPUT@ > @1@'.format(scdoc.path(), output),
      ],
      install: true,
      install_dir: '@0@/man@1@'.format(mandir, section),
    )
  endforeach
endif

subdir('etc')
