# platformd-secretd

platformd-secretd is a Secret Service provider for Linux desktop sessions — an
implementation of the freedesktop.org Secret Service API
(`org.freedesktop.secrets`) that binds secret release to platform-authentication
state. It is the first component of platformd (see `centricd-os`), written in C
against libsystemd (sd-bus, sd-event, sd-login, sd-journal, sd-varlink) and built
with meson.

An item may require that the platform be in a trusted state: its release is then
gated on the `local-trusted-session` verdict from platformd-trustd, and if that
verdict has lapsed the caller is asked to prove presence through platformd-verifyd
— a fingerprint, say — before the secret is released.

It provides two programs:

| Program | Role |
| --- | --- |
| `platformd-secretd` | the daemon; owns `org.freedesktop.secrets` on the session bus |
| `secretctl` | command-line client to inspect and manage it |

## Requirements

- libsystemd ≥ 257 — sd-bus, sd-event, sd-login, sd-journal, sd-varlink
- OpenSSL (libcrypto) ≥ 3.0 — encryption at rest and the DH session transport
- meson ≥ 1.1, ninja, and a C11 compiler
- polkit (optional, build time) — installs the fresh-verification action
- platformd-trustd, platformd-verifyd (optional, runtime) — needed only for items that gate on a trusted platform

## Build

```sh
meson setup build --prefix=/usr
ninja -C build
sudo meson install -C build
systemctl --user enable --now platformd-secretd.service
```

`--prefix=/usr` installs as a system component would expect: `secretctl` in
`/usr/bin`, the user service under `/usr/lib/systemd/user`, and the D-Bus service
and polkit action where the session bus and polkit look for them. Binaries are
produced under `build/src/secret/`.

## Documentation

[`docs/secret-service.md`](docs/secret-service.md) — design and interface reference.

## Status

The daemon implements the Secret Service collections, items, sessions, and
prompts used by libsecret clients. It supports AES-256-GCM storage under a
systemd credential, the encrypted Secret Service session transport, persistent
collections and items, and item release policies. Protected reads can require an
interactive polkit verification or a platformd-trustd verdict refreshed through
platformd-verifyd. These step-up operations are asynchronous. Transport sessions
and prompts are bound to the D-Bus client that created them, and a mutation
fails if the updated store cannot be written.

## License

LGPL-2.1-or-later
