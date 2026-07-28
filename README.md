# platformd-secretd

platformd-secretd is a Secret Service provider for Linux user sessions. It
implements `org.freedesktop.secrets` and is compatible with libsecret clients.
The daemon stores collections and items, tracks the logind lock state, and may
apply platform authentication policy to individual items.

The `platformd.policy` item attribute accepts:

- `fresh-verification`, evaluated by platformd-trustd as
  `fresh-user-verification`
- `trusted-platform`, evaluated by platformd-trustd as
  `local-trusted-session`

When trustd reports missing or stale verification, the daemon asks
platformd-verifyd to verify the user and then evaluates the policy again.
Unprotected items do not require either service. Protected items remain
unavailable when a required service or eligible logind session is unavailable.

`secretctl` reports provider and session state and can list, lock, or unlock the
default collection. Applications should use libsecret or `secret-tool` to store
and retrieve secrets.

## Requirements

- libsystemd 257 or newer
- OpenSSL 3.0 or newer
- Meson 1.1 or newer
- polkit for interactive collection unlock
- platformd-trustd and platformd-verifyd for protected items

## Building

```sh
meson setup build --prefix=/usr
meson compile -C build
sudo meson install -C build
```

Only one service may own `org.freedesktop.secrets` in a user session. Enable
platformd-secretd after disabling any other Secret Service provider:

```sh
systemctl --user enable --now platformd-secretd.service
```

See [docs/secret-service.md](docs/secret-service.md) and the
`platformd-secretd.service(8)` and `secretctl(1)` manual pages.

## License

LGPL-2.1-or-later
