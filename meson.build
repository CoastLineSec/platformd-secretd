project('platformd', 'c',
        version : '0.1.4',
        license : 'LGPL-2.1-or-later',
        meson_version : '>= 1.1',
        default_options : [
                'c_std=gnu11',
                'warning_level=2',
        ])

add_project_arguments('-D_GNU_SOURCE', '-Wno-unused-parameter', language : 'c')

libsystemd = dependency('libsystemd', version : '>= 257')
libcrypto = dependency('libcrypto', version : '>= 3.0')

subdir('src/secret')
subdir('man')

conf = configuration_data()
conf.set('LIBEXECDIR', get_option('prefix') / get_option('libexecdir'))

systemd = dependency('systemd', required : false)
systemd_user_unit_dir = systemd.found() ? systemd.get_variable(pkgconfig : 'systemduserunitdir') : get_option('prefix') / 'lib/systemd/user'
configure_file(
        input : 'units/platformd-secretd.service.in',
        output : 'platformd-secretd.service',
        configuration : conf,
        install : true,
        install_dir : systemd_user_unit_dir,
)

dbus = dependency('dbus-1', required : false)
dbus_services_dir = dbus.found() ? dbus.get_variable(pkgconfig : 'session_bus_services_dir') : get_option('datadir') / 'dbus-1/services'
configure_file(
        input : 'units/org.freedesktop.secrets.service.in',
        output : 'org.freedesktop.secrets.service',
        configuration : conf,
        install : true,
        install_dir : dbus_services_dir,
)

polkit = dependency('polkit-gobject-1', required : false)
polkit_action_dir = polkit.found() ? polkit.get_variable(pkgconfig : 'actiondir') : '/usr/share/polkit-1/actions'
install_data('polkit/io.platformd.secret1.policy', install_dir : polkit_action_dir)
