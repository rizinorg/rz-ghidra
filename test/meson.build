
rz_test_bin = find_program('rz-test', required: true)

env = environment()
env.set('RZ_LIBR_PLUGINS', plugin_dir)
env.set('SLEIGHHOME', sleighhome)


test('testbins', rz_test_bin, args: ['-L', join_paths(meson.current_source_dir(), 'db', 'extras')], env: env, timeout: 10)




