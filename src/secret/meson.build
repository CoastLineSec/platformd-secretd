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

test('vault', executable(
        'test-vault',
        'test-vault.c',
        'vault.c',
        c_args : ['-DVAULT_TESTING'],
        dependencies : libcrypto,
))
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

socket_guard_test = executable('test-socket-guard', 'test-socket-guard.c')
test('vault-key', find_program('sh'),
     args : [meson.current_source_dir() / 'test-vault-key.sh', secretd],
     timeout : 120)

locking_test = executable('test-locking', 'test-locking.c', dependencies : libsystemd)
test('locking', find_program('sh'),
     args : [meson.current_source_dir() / 'test-locking.sh', secretd, locking_test],
     timeout : 60)

lock_state_test = executable('test-lock-state', 'test-lock-state.c', 'vault.c',
     dependencies : [libsystemd, libcrypto])
test('lock-state', find_program('sh'),
     args : [meson.current_source_dir() / 'test-lock-state.sh', lock_state_test],
     timeout : 60)

stepup_test = executable('test-stepup', 'test-stepup.c', 'vault.c',
     dependencies : [libsystemd, libcrypto])
test('stepup', find_program('sh'),
     args : [meson.current_source_dir() / 'test-stepup.sh', stepup_test],
     timeout : 60)

test('bulk-policy', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-bulk-policy.sh',
             secretd_test,
             policy_service_test,
             security_test,
     ],
     timeout : 60)

test('environment', find_program('sh'),
     args : [
             meson.current_source_dir() / 'test-environment.sh',
             socket_guard_test,
             secretd,
             secretd_test,
             policy_service_test,
             secretctl,
             security_test,
     ],
     timeout : 180)
