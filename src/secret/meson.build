secretctl = executable(
        'secretctl',
        'secretctl.c',
        c_args : ['-DPROGRAM_VERSION="@0@"'.format(meson.project_version())],
        dependencies : libsystemd,
        install : true,
)

secretd = executable(
        'platformd-secretd',
        'secretd.c',
        'vault.c',
        dependencies : [libsystemd, libcrypto],
        install : true,
        install_dir : get_option('libexecdir'),
)

secretd_test = executable(
        'platformd-secretd-test',
        'secretd.c',
        'vault.c',
        c_args : ['-DSECRETD_TESTING'],
        dependencies : [libsystemd, libcrypto],
)

policy_service_test = executable(
        'test-policy-service',
        'test-policy-service.c',
        dependencies : libsystemd,
)

test('vault', executable('test-vault', 'test-vault.c', 'vault.c', dependencies : libcrypto))
security_test = executable('test-security', 'test-security.c', dependencies : libsystemd)
test('integration', find_program('sh'),
     args : [meson.current_source_dir() / 'test-integration.sh', secretd],
     timeout : 60)
test('security', find_program('sh'),
     args : [meson.current_source_dir() / 'test-security.sh', secretd, security_test],
     timeout : 60)
test('malformed-store', find_program('sh'),
     args : [meson.current_source_dir() / 'test-malformed-store.sh', secretd],
     timeout : 120)
test('policy', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-policy.sh',
             secretd_test,
             policy_service_test,
             secretctl,
     ],
     timeout : 120)
