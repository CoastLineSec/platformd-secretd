# The platformd Secret Service

`platformd-secretd` implements the freedesktop.org Secret Service API
(`org.freedesktop.secrets`) for Linux desktop sessions. Unlike a conventional
keyring, its purpose is not storage but **authentication-bound release**: it is
built so that handing a secret to a caller can be gated on the state of the local
platform-authentication session — recent user verification, lock/unlock, and the
identity of the calling process.

This document describes the provider, the D-Bus interface it serves, the
`secretctl` client, the storage model, the trust model, and the security
properties it does and does not provide. Terms follow the `platformd` claim
vocabulary — `observed`, `declared`, `measured`, `verified`, `policy-satisfied`,
`trusted` — and default to `policy-satisfied`. Nothing here is `trusted` unless a
trust root, policy, threat model, and enforcement mechanism are all named, and no
security property is a current fact unless the section says it is implemented.

## Overview

The freedesktop.org Secret Service API is the cross-desktop D-Bus interface
through which applications — browsers, mail clients, and anything using
`libsecret` — store and retrieve passwords and other small secrets. The common
providers are GNOME Keyring and KWallet.

Those providers store secrets well, but they define no platform-authentication
model. A collection is unlocked once, typically with the login password, and then
stays unlocked for the lifetime of the session; release is gated only on the
caller sharing the session bus under the same UID. There is no notion of boot
state, of lock/unlock as a security transition, of how recently the user
authenticated, of the identity of the calling process, or of binding a secret to
hardware. `systemd-creds` adds TPM-backed encryption, but for *service*
credentials passed to units — it is not a desktop, application-facing provider.

`platformd-secretd` is a Secret Service provider designed around those missing
properties. It implements the standard API so unmodified clients work, and adds a
**trust gate** in front of every release and protected mutation, so that what a
caller may obtain depends on a named, inspectable local policy rather than on bus
access alone.

## Architecture

The component is two programs, in the manner of a systemd daemon and its
companion tool (compare `systemd-homed` and `homectl`):

- **`platformd-secretd`** — the daemon. A user-session service. It connects to
  the session bus with `sd-bus`, runs an `sd-event` loop, and owns the well-known
  name `org.freedesktop.secrets`. It announces readiness with `sd_notify(3)` and
  exits cleanly on `SIGTERM`/`SIGINT`.
- **`secretctl`** — the command-line client, used to inspect and manage the
  provider.

The daemon serves the standard Secret Service object hierarchy:

```
/org/freedesktop/secrets                        org.freedesktop.Secret.Service
/org/freedesktop/secrets/collection/default     org.freedesktop.Secret.Collection
/org/freedesktop/secrets/aliases/default        (alias to the default collection)
/org/freedesktop/secrets/collection/default/N   org.freedesktop.Secret.Item
/org/freedesktop/secrets/session/N              org.freedesktop.Secret.Session
```

The default collection is served at both its canonical path and the
`aliases/default` path, because `libsecret` resolves the default collection
through the alias path.

## The D-Bus interface

`platformd-secretd` implements the interfaces below. Signatures are given in D-Bus
type-string notation. The API is the freedesktop standard; the "Behaviour" column
describes this provider.

### org.freedesktop.Secret.Service

Object: `/org/freedesktop/secrets`.

| Member | Signature | Behaviour |
| --- | --- | --- |
| `OpenSession` | `(sv) → (vo)` | Negotiates a transport session. Both `plain` and the encrypted `dh-ietf1024-sha256-aes128-cbc-pkcs7` (1024-bit MODP Diffie-Hellman + HKDF-SHA256 → AES-128-CBC/PKCS7, byte-compatible with `libsecret`) are implemented; unknown algorithms return `org.freedesktop.DBus.Error.NotSupported`, and `libsecret` falls back to `plain`. |
| `SearchItems` | `(a{ss}) → (ao ao)` | Returns matching item paths split into `unlocked` and `locked`. An item matches when every requested attribute is present with an equal value. |
| `GetSecrets` | `(ao o) → (a{o(oayays)})` | Returns the secrets for several items in one call, keyed by item path. |
| `ReadAlias` | `(s) → (o)` | Resolves an alias name; `default` returns the default collection, anything else returns `/`. |
| `Unlock` / `Lock` | `(ao) → (ao o)` | Trust transitions (see [Trust model](#trust-model)). `Lock` marks the collection locked; `Unlock` releases it **only while the desktop session is unlocked** — while the screen is locked, `Unlock` is refused. Clearing an explicit `Lock` returns a `Prompt` that re-authenticates via polkit. |
| `CreateCollection` | `(a{sv} s) → (o o)` | Creates a named collection from the `org.freedesktop.Secret.Collection.Label` property (the `default` alias returns the built-in default). Additional collections live alongside the default and are persisted. |
| `SetAlias` | `(s o) → ()` | Accepted; the default alias is fixed. |
| `Collections` | property `ao` | The collections offered by the service. |

### org.freedesktop.Secret.Collection

Objects: `/org/freedesktop/secrets/collection/default` (also served at the
`aliases/default` alias) and `/org/freedesktop/secrets/collection/cN` for
additional collections created via `CreateCollection`.

| Member | Signature | Behaviour |
| --- | --- | --- |
| `CreateItem` | `(a{sv} (oayays) b) → (o o)` | Creates or, when `replace` is true and the attribute set matches, updates an item. Reads the `org.freedesktop.Secret.Item.Label` and `…Attributes` properties from the input. |
| `SearchItems` | `(a{ss}) → (ao)` | As for the service, scoped to this collection. |
| `Delete` | `() → (o)` | Deletes the collection and its items; refused for the default collection. |
| `Items` | property `ao` | The item paths in the collection. |
| `Label`, `Locked`, `Created`, `Modified` | properties `s`, `b`, `t`, `t` | Collection metadata. |

### org.freedesktop.Secret.Item

Objects: `/org/freedesktop/secrets/collection/default/N`.

| Member | Signature | Behaviour |
| --- | --- | --- |
| `GetSecret` | `(o) → ((oayays))` | Returns the secret. **This is the call the trust gate guards** (see below). |
| `SetSecret` | `((oayays)) → ()` | Replaces the secret value and content type. |
| `Delete` | `() → (o)` | Removes the item. |
| `Attributes`, `Label`, `Locked`, `Created`, `Modified` | properties | Item metadata. |

The secret structure `(oayays)` is `(session, parameters, value, content-type)`.
With the `plain` transport `parameters` is empty and `value` is the secret bytes
verbatim. With the DH transport `value` is AES-128-CBC ciphertext and
`parameters` carries the IV.

### org.freedesktop.Secret.Session

Objects: `/org/freedesktop/secrets/session/N`. Provides `Close()`. One session is
created per `OpenSession`.

### org.freedesktop.Secret.Prompt

Objects: `/org/freedesktop/secrets/prompt/N`. A `Prompt` is how the service asks
the user to authorise an operation. `Service.Unlock` returns one when an explicit
`Service.Lock` is in effect; `Prompt(window-id)` re-authenticates the caller via
polkit and then emits `Completed(dismissed, result)`, and `Dismiss()` cancels it.

## secretctl

`secretctl` is the inspection and management client, in the grammar of
`homectl(1)` / `loginctl(1)`. Day-to-day secret access uses the standard
`secret-tool(1)` client and `libsecret`; the service lifecycle is managed with
`systemctl --user`. `secretctl` covers what those do not: inspecting and
controlling the provider itself.

### secretctl status

Read-only. Reports, without claiming the bus name or storing anything:

1. **Provider** — which connection, if any, owns `org.freedesktop.secrets`, and
   the owning process where it can be resolved.
2. **Session** — the `systemd-logind` session, seat, type, class and active state
   for the calling login, and the *declared* lock state (`login1` `LockedHint`).
3. **Caller** — a caller-identity probe of the invoking process: UID, PID, unit,
   control group, and the resulting identity-evidence grade.

The `list`, `lock`, and `unlock` verbs are implemented.

## Varlink

Alongside the D-Bus Secret Service, the daemon exposes a small **read-only
administrative interface over Varlink**, `io.platformd.Secret`, the way systemd's
own services do (`io.systemd.Home`, `io.systemd.Resolve`, …). It is served on
`$XDG_RUNTIME_DIR/platformd-secretd/io.platformd.Secret` and carries **no
secrets** — only status and metadata:

- `GetStatus()` — lock state (effective / desktop / manual), item count,
  whether the store is encrypted, the freshness window, and the tracked logind
  session;
- `ListItems()` — item metadata: label, attributes, and timestamps.

```sh
varlinkctl call "$XDG_RUNTIME_DIR/platformd-secretd/io.platformd.Secret" \
    io.platformd.Secret.GetStatus '{}'
```

The schema lives in `src/secret/io.platformd.Secret.varlink`.

## Storage model

The store is persisted to `$XDG_DATA_HOME/platformd-secretd/secrets` (mode
`0600`) in a versioned container:

```text
"PLTFSECR" | u32 version | u32 cipher | [cipher 1: nonce | tag] | u32 len | payload
```

With `cipher = 0` the payload (the serialized items) is stored in the clear; with
`cipher = 1` it is sealed with **AES-256-GCM** (`libcrypto`/OpenSSL) under a
single **vault key**. Writes are atomic (write-temp-then-rename). The plaintext
payload and the vault key are wiped from memory with `OPENSSL_cleanse` after use,
the vault key is held `mlock(2)`-ed, and the unit sets `LimitCORE=0` so secrets
cannot reach a coredump.

### The vault key

The vault key is provided out of band as a **systemd credential**: the daemon
reads 32 raw bytes from `$CREDENTIALS_DIRECTORY/vault-key` (or, for development,
the file named by `$SECRETD_VAULT_KEY_FILE`). Delivering it with
`LoadCredentialEncrypted=` has `systemd` decrypt it at service start from a
`systemd-creds` blob — bound to the host key or, for at-rest protection against a
stolen disk, to the **TPM** — so the key never lives beside the data. With no
credential the store stays in the clear, which is the right choice when the home
is already encrypted (a `systemd-homed` `luks`/`fscrypt` home): there, encryption
at rest is the home's job and a second layer adds nothing.

| Home | Vault key | Result |
| --- | --- | --- |
| homed `luks` / `fscrypt` | none | plaintext store inside an already-encrypted home |
| regular / homed `directory` | systemd credential (host- or TPM-bound) | AES-256-GCM store; key protected outside the home |

Planned refinements: a passphrase mode (Argon2id, via `vault_derive_key`) for
interactive unlock; per-item keys, so individual items can be gated
independently, which pairs with the item-level trust policy and does not
change the container format; and auto-selecting the mode from the user's
`systemd-homed` storage backend.

**Recovery.** The vault key is the sole recovery anchor: if the credential is
lost, encrypted secrets are unrecoverable. A host-bound credential does not
survive re-imaging or moving the disk to another machine, and a TPM-bound
credential does not survive TPM state changes without an enrolled recovery path.
A deployment that needs recoverability must escrow the key material itself.

## Trust model

`platformd-secretd` does not decide trust; it **consumes** a trust signal and
enforces a named policy on top of it. This is the line that separates it from a
keyring. The boundary is a **trust gate**, evaluated before any operation that
would yield plaintext or mutate protected state:

```c
typedef enum {
        DECISION_ALLOW,
        DECISION_DENY,
        DECISION_NEEDS_VERIFICATION,
} Decision;

typedef struct ReleaseRequest {
        CallerIdentity caller;       /* see "Caller identity" */
        const char    *collection;
        ItemPolicy     item_policy;  /* the item's release requirement */
        Operation      operation;    /* OP_READ, OP_MUTATE, OP_UNLOCK */
} ReleaseRequest;

typedef struct TrustVerdict {
        Decision    decision;
        const char *policy;          /* the named policy applied */
        const char *reason;          /* human-explainable */
        uint64_t    expires_usec;    /* 0 = no expiry */
} TrustVerdict;

/* Pluggable backend: a local logind session model, and platformd-trustd's verdict for platform-trust policies. */
typedef struct TrustGate {
        int (*evaluate)(struct TrustGate *gate, const ReleaseRequest *req, TrustVerdict *ret);
        void *userdata;
} TrustGate;
```

Every verdict is explainable: which policy was applied, and why. `secretctl`
prints this.

**Item policy.** Each item declares how strongly its release is gated:

- `while-session-active` — released while a logind session is active (weakest);
- `while-unlocked` — released only while the collection is unlocked;
- `fresh-verification` — released only after a recent verification event;
  otherwise the gate returns `NEEDS_VERIFICATION` and the service raises a
  `Prompt`.

**Named policies.**

- `credential-release-basic` — active local session, unlocked, and caller-identity
  grade meets the item's minimum. Requires no boot evidence, TPM, or verified
  authentication method.
- `fresh-user-verification` — `credential-release-basic` plus a verification event
  within a freshness window and a session not marked stale by suspend/resume.
- `trusted-platform` — release is gated on `platformd-trustd`'s
  `local-trusted-session` verdict: a verified-local boot, a verified user identity,
  and a fresh user verification. This is the boot- and TPM-aware policy the
  session-only policies above stop short of.

**The gate backend.** Session-based policies are decided locally from what can be
honestly observed: a logind session that is active (*observed*) and unlocked
(*declared*, from `login1` `LockedHint`), within a freshness window. The
`trusted-platform` policy is decided by `platformd-trustd`, which secretd consumes
over Varlink (`io.platformd.Trust.EvaluatePolicy`, `local-trusted-session`); the
`TrustGate` indirection keeps that behind one interface, without changing the
storage, the D-Bus surface, or the item policies. `Lock`/`Unlock` map onto the
session model: unlocking records a verification event; locking marks items
unavailable and clears cached plaintext.

**Enforcement (as implemented).** The gate is `trust_gate()`, evaluated in
`Item.GetSecret`. Effective lock state is the OR of two sources: the logind
session lock (`desktop_locked`, driven by the `login1` session `Lock`/`Unlock`
signals and `LockedHint`) and an explicit `Service.Lock` (`manual_locked`).
Crucially, **`Service.Unlock` refuses while `desktop_locked`** — a client cannot
release secrets while the screen is locked; the only key is unlocking the
session itself, which takes real authentication. Items opt into stronger gating
with attributes: `platformd.policy=fresh-verification` (released only within a
freshness window of a genuine desktop unlock), `platformd.policy=trusted-platform`
(gated on `platformd-trustd`'s `local-trusted-session` verdict), and
`platformd.min-grade` (a caller-grade floor). A stale `fresh-verification` read
triggers an interactive
**polkit** check (`io.platformd.secret1.verify-fresh`, `auth_self`): the desktop
agent prompts the user, and only a real authentication refreshes the freshness
and releases the item. A stale `trusted-platform` read instead steps up through
**`platformd-verifyd`**, which proves the user present (fingerprint, face, …) and
refreshes `platformd-trustd`; the item releases only if the platform is then
trusted. Nothing an unattended client can do releases either.

**Protected mutation.** The gate guards mutation as well as release. `SetSecret`,
`SetAttributes`, `Delete`, and a replace-on-`CreateItem` of an item that carries a
`platformd.*` attribute all require that item's policy to hold — otherwise a caller
could strip the policy with `SetAttributes` and then read freely, or destroy a
gated secret while its policy is unsatisfied. A collection `Delete` is refused if
it would take a gated item down with it. Mutations do not themselves step up (the
release path offers that); they require the policy to be satisfied *now*.

**The step-up is asynchronous.** A stale read does not block: `GetSecret` defers
its D-Bus reply and drives the polkit prompt or `platformd-verifyd` call on the
event loop, so the daemon keeps serving every other client while the user responds
at the reader. The requesting client is still bound by its own D-Bus method
timeout; the Secret Service `Prompt` object, which has no client-side timeout, is
the natural home for a fully interactive unlock. `GetSecrets` (the bulk read)
never steps up — it silently returns only the items that are releasable right now,
as the specification's batch semantics intend; a caller that needs a step-up uses
per-item `GetSecret`.

## Caller identity

Authenticating the user is not enough; the provider must also identify the
**caller**, which on Linux is the hard part. Caller identity is therefore treated
as graded evidence, never as a binary, and UID alone is never taken as sufficient
for high-value release. Evidence is gathered from D-Bus peer credentials and
`sd-login` (UID, PID, control group, systemd unit, and, where present, a Flatpak
or XDG-portal application identifier and an LSM label) and graded:

```
unknown        not enough evidence
same-user-weak ordinary unsandboxed process under our UID
systemd-unit   belongs to a named systemd unit
dbus-subject   D-Bus peer credentials known
sandboxed-app  Flatpak / portal application identifier available
signed-app     future; requires a package/signature policy
```

The provider records and reports this grade for every request. Where isolation is
weak (`same-user-weak`), it does not pretend the identity is strong; it releases
only what the item policy permits at that grade.

## Security considerations

Stated honestly, by what the implementation addresses and what it does not.

**Addressed.**

- A same-user process reading high-value secrets without a recent verification —
  bounded by the `fresh-verification` item policy and the trust gate.
- Secrets at rest on a powered-off or stolen disk — addressed by encryption with a
  passphrase-derived (later TPM-bound) vault key.
- A locked session — `Lock` makes items unavailable and clears cached plaintext.

**Not addressed (degraded or unsupported, not hidden).**

- Local root on a mutable system can read process memory and on-disk state.
- Without a sandbox/portal model, same-user processes share the bus, files, and
  environment; caller identity can be graded but `same-user-weak` cannot be made
  strong.
- Spoofed prompts before a trusted-UI mechanism exists.
- Without a TPM there is no hardware binding and no boot-aware policy; such states
  are reported as `degraded` for policies that need them.

These states are surfaced explicitly rather than papered over with security
language.

## Relationship to systemd and platformd

`platformd-secretd` composes existing mechanisms rather than replacing them.
`platformd` is a placeholder for `systemd`, so the component is shaped exactly as
systemd shapes its own:

| systemd shape | this component |
| --- | --- |
| daemon `systemd-<noun>d` | `platformd-secretd` |
| companion `<noun>ctl` | `secretctl` |
| unit `*.service` (user) | `platformd-secretd.service` |
| D-Bus `org.freedesktop.<noun>1` | `org.freedesktop.secrets` (the standard provider API) |
| Varlink `io.systemd.<Noun>` | `io.platformd.Secret` (admin/service interface) |
| polkit actions | `io.platformd.secret1.*` (the fresh-verification action) |
| credentials / TPM | `systemd-creds`, `systemd-cryptenroll` |
| logging | `systemd-journald` |

What it consumes, and from where:

```
systemd-logind     session active / lock state             (now)
systemd-homed      home activation as a vault-key anchor    (later)
systemd-creds /    TPM-sealed vault key                     (later)
  cryptenroll
platformd-trustd   the trusted-platform verdict             (now)
platformd-verifyd  presence step-up for a stale verdict     (now)
polkit             step-up for a lapsed session             (now)
```

`platformd-secretd` does not replace PAM, `systemd-logind`, `systemd-homed`,
polkit, or the kernel keyring, and it does not own the TPM; it consumes TPM
sealing through systemd.

## Status

Functional and feature-complete for the freedesktop.org Secret Service API: the
Service, collections (the default plus additional named ones), items, sessions,
and prompts, interoperable with libsecret and `secret-tool`. Secrets are encrypted
in transit (the DH session transport) and at rest (AES-256-GCM). The trust gate is
enforced — the logind session lock, graded caller identity, and the
`fresh-verification` and `trusted-platform` item policies; the latter consumes
`platformd-trustd`'s verdict and steps up through `platformd-verifyd`. `secretctl`
and the `io.platformd.Secret` Varlink interface round it out.

A TPM-bound vault key (via `systemd-cryptenroll`) remains future work; today the
vault key is delivered as a systemd credential, or the store rides on an
already-encrypted home.
