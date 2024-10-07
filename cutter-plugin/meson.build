
rz_ghidra_cutter_headers = [
  'RzGhidraDecompiler.h',
  'RzGhidraPlugin.h',
  ]

rz_ghidra_cutter_sources = [
  'RzGhidraDecompiler.cpp',
  'RzGhidraPlugin.cpp',
  ] + rz_ghidra_cutter_headers

# FIXME: this is not portable
cutter_deps = declare_dependency(
  dependencies: [
    dependency('Qt6Core'),
    dependency('Qt6Widgets'),
    dependency('Qt6Core5Compat'),
    dependency('Qt6Gui'),
    dependency('Qt6SvgWidgets'),
    dependency('Qt6Network'),
    dependency('Qt6OpenGL'),
    dependency('Qt6OpenGLWidgets'),
    dependency('rz_core'),
    dependency('rz_reg'),
    dependency('rz_flag'),
    dependency('rz_hash'),
    dependency('rz_bin'),
    dependency('rz_bp'),
    dependency('rz_io'),
    dependency('rz_search'),
    dependency('rz_sign'),
    dependency('rz_cons'),
    dependency('rz_lang'),
    dependency('rz_socket'),
    dependency('rz_type'),
    dependency('rz_debug'),
    dependency('rz_il'),
    dependency('rz_demangler'),
    dependency('rz_util'),
    dependency('rz_main'),
    dependency('rz_crypto'),
    dependency('rz_config'),
    dependency('rz_egg'),
    dependency('rz_syscall'),
    dependency('rz_magic'),
    dependency('libgvc'),
    dependency('python3-embed'),
    ],
  compile_args: [
    '-I/usr/include/cutter',
    '-I/usr/include/cutter/common',
    '-I/usr/include/cutter/core',
    '-I/usr/include/cutter/dialogs',
    '-I/usr/include/cutter/menus',
    '-I/usr/include/cutter/plugins',
    '-I/usr/include/cutter/tools',
    '-I/usr/include/cutter/widgets',
    ],
)

qt6 = import('qt6', required: true)
moc_sources = []
common_cpp_args = []

foreach moc : rz_ghidra_cutter_headers
  moc_sources += qt6.compile_moc(headers: moc, extra_args: common_cpp_args, dependencies: rz_deps + cutter_deps + [ ghidra_dep, ] )
endforeach

rz_ghidra_cutter_mod = shared_module('rz_ghidra_cutter',
  rz_ghidra_cutter_sources + moc_sources,
  install: true,
  install_dir: join_paths(datadir, 'rizin', 'cutter', 'plugins', 'native'),
  cpp_args: [ '-DRZ_GHIDRA_SLEIGHHOME_DEFAULT="@0@"'.format(sleighhome)],
  dependencies: rz_deps + cutter_deps + [ ghidra_dep, ],
  )

cutter_ghidra_dep_cargs = ['-DRZ_GHIDRA_SLEIGHHOME_DEFAULT="@0@"'.format(sleighhome)]

cutter_ghidra_dep = declare_dependency(
  link_with: rz_ghidra_cutter_mod,
  dependencies: [ ghidra_dep ],
  include_directories: [ '.' ],
  )
