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
        'policy.c',
        dependencies : [libsystemd, libcrypto],
        install : true,
        install_dir : get_option('libexecdir'),
)

secretd_test = executable(
        'platformd-secretd-test',
        'secretd.c',
        'vault.c',
        'policy.c',
        'test-session.c',
        c_args : ['-DSECRETD_TESTING'],
        link_args : '-Wl,--wrap=sd_uid_get_display',
        dependencies : [libsystemd, libcrypto],
)

secretd_isolated = executable(
        'platformd-secretd-isolated',
        'secretd.c', 'vault.c', 'policy.c', 'test-session.c',
        link_args : '-Wl,--wrap=sd_uid_get_display',
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
test('storage', executable('test-storage', 'test-storage.c', 'vault.c', 'policy.c',
     dependencies : [libsystemd, libcrypto],
     link_args : ['-Wl,--wrap=read', '-Wl,--wrap=__read_chk', '-Wl,--wrap=write', '-Wl,--wrap=fsync', '-Wl,--wrap=rename']))
collection_test = executable('test-collection', 'test-collection.c', 'vault.c', 'policy.c',
     dependencies : [libsystemd, libcrypto],
     link_args : ['-Wl,--wrap=write', '-Wl,--wrap=fsync', '-Wl,--wrap=rename'])
test('collection', find_program('sh'),
     args : [meson.current_source_dir() / 'test-lock-state.sh', collection_test], timeout : 60)
security_test = executable('test-security', 'test-security.c', dependencies : libsystemd)
test('integration', find_program('sh'),
     args : [meson.current_source_dir() / 'test-integration.sh', secretd_isolated],
     timeout : 60)
test('lifecycle', find_program('sh'),
     args : [meson.current_source_dir() / 'test-lifecycle.sh', secretd_isolated], timeout : 60)
home_service_test = executable('test-home-service', 'test-home-service.c', dependencies : libsystemd)
test('home-storage', find_program('sh'),
     args : [meson.current_source_dir() / 'test-home-storage.sh', secretd_isolated, home_service_test],
     timeout : 30)
cli_service_test = executable('test-cli-service', 'test-cli-service.c', dependencies : libsystemd)
test('cli', find_program('sh'),
     args : [meson.current_source_dir() / 'test-cli.sh', secretctl, cli_service_test], timeout : 60)
test('security', find_program('sh'),
     args : [meson.current_source_dir() / 'test-security.sh', secretd_isolated, security_test],
     timeout : 60)
test('malformed-store', find_program('sh'),
     args : [meson.current_source_dir() / 'test-malformed-store.sh', secretd_isolated],
     timeout : 120)
test('store-status', find_program('sh'),
     args : [meson.current_source_dir() / 'test-store-status.sh', secretd_isolated],
     timeout : 60)
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
     args : [meson.current_source_dir() / 'test-vault-key.sh', secretd_isolated],
     timeout : 120)

locking_test = executable('test-locking', 'test-locking.c', dependencies : libsystemd)
test('locking', find_program('sh'),
     args : [meson.current_source_dir() / 'test-locking.sh', secretd_isolated, locking_test],
     timeout : 60)

lock_state_test = executable('test-lock-state', 'test-lock-state.c', 'vault.c', 'policy.c',
     dependencies : [libsystemd, libcrypto])
test('lock-state', find_program('sh'),
     args : [meson.current_source_dir() / 'test-lock-state.sh', lock_state_test],
     timeout : 60)

session_collection_test = executable('test-session-collection', 'test-session-collection.c', 'vault.c', 'policy.c',
     dependencies : [libsystemd, libcrypto])
test('session-collection', find_program('sh'),
     args : [meson.current_source_dir() / 'test-lock-state.sh', session_collection_test],
     timeout : 60)

session_daemon_test = executable('platformd-secretd-session-test',
     'secretd.c', 'vault.c', 'policy.c', 'test-session.c', 'test-login.c',
     link_args : ['-Wl,--wrap=sd_uid_get_display', '-Wl,--wrap=sd_uid_get_sessions',
                  '-Wl,--wrap=sd_session_get_uid', '-Wl,--wrap=sd_session_get_class',
                  '-Wl,--wrap=sd_session_get_state', '-Wl,--wrap=sd_bus_request_name'],
     dependencies : [libsystemd, libcrypto])
session_client_test = executable('test-session-client', 'test-session-client.c',
     dependencies : dependency('libsecret-1'))
test('session-client', find_program('sh'),
     args : [meson.current_source_dir() / 'test-session-collection.sh', session_daemon_test, session_client_test],
     timeout : 60)

stepup_test = executable('test-stepup', 'test-stepup.c', 'vault.c', 'policy.c',
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
             secretd_isolated,
             secretd_test,
             policy_service_test,
             secretctl,
             security_test,
     ],
     timeout : 180)
