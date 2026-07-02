# platformd-secretd

platformd-secretd is a Secret Service provider for Linux desktop sessions — an
implementation of the freedesktop.org Secret Service API
(`org.freedesktop.secrets`) that binds secret release to platform-authentication
state. It is the first component of platformd (see `centricd-os`), written in C
against libsystemd (sd-bus, sd-event, sd-login, sd-journal, sd-varlink) and built
with meson.

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

## Build

```sh
meson setup build
ninja -C build
systemctl --user enable --now platformd-secretd.service
```

Binaries are produced under `build/src/secret/`.

## Documentation

[`docs/secret-service.md`](docs/secret-service.md) — design and interface reference.

## Status

Functional and feature-complete for a first release: the full Secret Service API
(collections, items, sessions, prompts) for any libsecret client, encryption at
rest (AES-256-GCM under a systemd-credential key) and in transit (the DH session
transport), a persistent store, and the trust gate — secret release tracks the
logind session lock, grades caller identity, and can require a polkit step-up.
`secretctl` and a Varlink admin interface round it out.

## License

LGPL-2.1-or-later
