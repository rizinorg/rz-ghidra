project('rz-ghidra', ['cpp'],
  )

libdir = get_option('libdir')
plugin_dir = join_paths(libdir, 'rizin', 'plugins')
datadir = get_option('datadir')
prefix = get_option('prefix')
sleighhome=join_paths(prefix, libdir, 'rizin', 'plugins', 'rz_ghidra_sleigh')

rz_ghidra_plugin_source = [
  join_paths('src', 'PrettyXmlEncode.cpp'),
  join_paths('src', 'CodeXMLParse.cpp'),
  join_paths('src', 'PcodeFixupPreprocessor.cpp'),
  join_paths('src', 'ArchMap.cpp'),
  join_paths('src', 'RizinPrintC.cpp'),
  join_paths('src', 'RizinTypeFactory.cpp'),
  join_paths('src', 'SleighAsm.cpp'),
  join_paths('src', 'SleighAnalysisValue.cpp'),
  join_paths('src', 'SleighInstruction.cpp'),
  join_paths('src', 'RizinCommentDatabase.cpp'),
  join_paths('src', 'RizinLoadImage.cpp'),
  join_paths('src', 'RizinScope.cpp'),
  join_paths('src', 'RzCoreMutex.cpp'),
  join_paths('src', 'RizinArchitecture.cpp'),
  join_paths('src', 'SleighInstruction.h'),
  join_paths('src', 'RizinLoadImage.h'),
  join_paths('src', 'ArchMap.h'),
  join_paths('src', 'RizinUtils.h'),
  join_paths('src', 'RizinCommentDatabase.h'),
  join_paths('src', 'PcodeFixupPreprocessor.h'),
  join_paths('src', 'RizinArchitecture.h'),
  join_paths('src', 'PrettyXmlEncode.h'),
  join_paths('src', 'SleighAnalysisValue.h'),
  join_paths('src', 'SleighAsm.h'),
  join_paths('src', 'rz_ghidra_internal.h'),
  join_paths('src', 'RizinPrintC.h'),
  join_paths('src', 'CodeXMLParse.h'),
  join_paths('src', 'RizinTypeFactory.h'),
  join_paths('src', 'rz_ghidra.h'),
  join_paths('src', 'RzCoreMutex.h'),
  join_paths('src', 'RizinScope.h'),
  ]

rz_deps = [
  dependency('rz_core'),
  dependency('rz_reg'),
  dependency('rz_flag'),
  dependency('rz_hash'),
  dependency('rz_bin'),
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
  ]

ghidra_subproj = subproject('ghidra', required: true)
ghidra_dep = ghidra_subproj.get_variable('ghidra_libdecomp_dep')
pugixml_dep = dependency('pugixml')

cutter_static = get_option('cutter-plugin').allowed()
enable_tests = get_option('enable-tests')

install_headers([join_paths('src', 'rz_ghidra.h')])

core_mod = library('core_ghidra',
  rz_ghidra_plugin_source + [ join_paths('src', 'core_ghidra.cpp') ],
  install: true,
  install_dir: plugin_dir,
  dependencies: rz_deps + [ ghidra_dep, pugixml_dep ],
  cpp_args: [ '-DRZ_GHIDRA_SLEIGHHOME_DEFAULT="@0@"'.format(sleighhome)],
  name_prefix: '',
  )

asm_mod = library('asm_ghidra',
  rz_ghidra_plugin_source + [
    join_paths('src', 'asm_ghidra.cpp'),
    ],
  install: true,
  install_dir: plugin_dir,
  link_with: core_mod,
  link_args: ['-Wl,-rpath,$ORIGIN'],
  dependencies: rz_deps + [ ghidra_dep, pugixml_dep ],
  cpp_args: [ '-DRZ_GHIDRA_SLEIGHHOME_DEFAULT="@0@"'.format(sleighhome)],
  name_prefix: '',
  )

analysis_mod = library('analysis_ghidra',
  rz_ghidra_plugin_source + [
    join_paths('src', 'analysis_ghidra.cpp'),
    ],
  install: true,
  install_dir: plugin_dir,
  link_with: core_mod,
  link_args: ['-Wl,-rpath,$ORIGIN'],
  dependencies: rz_deps + [ ghidra_dep, pugixml_dep ],
  cpp_args: [ '-DRZ_GHIDRA_SLEIGHHOME_DEFAULT="@0@"'.format(sleighhome)],
  name_prefix: '',
  )

rz_ghidra_dep = declare_dependency(
  link_with: [ asm_mod, analysis_mod, core_mod ],
  include_directories: '.',
  )

if cutter_static
  subdir('cutter-plugin')
endif

if enable_tests
  subdir('test')
endif


