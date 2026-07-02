# platformd-secretd — platform-auth-aware Secret Service provider.
# (Sources live here, in src/secret/, exactly as systemd keeps src/home/, etc.
#  The daemon binary `platformd-secretd` lands at M2; M1 is the secretctl CLI.)

executable(
        'secretctl',
        'secretctl.c',
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

# --- tests (meson test) ---
test('vault', executable('test-vault', 'test-vault.c', 'vault.c', dependencies : libcrypto))
test('integration', find_program('sh'),
     args : [meson.current_source_dir() / 'test-integration.sh', secretd],
     timeout : 60)
test('malformed-store', find_program('sh'),
     args : [meson.current_source_dir() / 'test-malformed-store.sh', secretd],
     timeout : 120)
