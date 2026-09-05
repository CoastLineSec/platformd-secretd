# platformd Secret Service

## Description

`platformd-secretd` provides the freedesktop.org Secret Service API on the user
bus. It owns `org.freedesktop.secrets` and stores secrets for applications using
libsecret or another compatible client.

The daemon provides:

- the standard Service, Collection, Item, Session, and Prompt interfaces
- plain and `dh-ietf1024-sha256-aes128-cbc-pkcs7` transport sessions
- persistent collections and items
- optional AES-256-GCM encryption for the store
- collection lock state derived from logind and explicit Service.Lock requests
- per-item release policy evaluated by platformd-trustd
- user verification through platformd-verifyd when trustd reports missing or
  stale verification
- a read-only Varlink interface for status and item metadata

`secretctl` inspects the provider and controls the default collection.

## D-Bus interface

The service uses this object hierarchy:

```text
/org/freedesktop/secrets
/org/freedesktop/secrets/collection/default
/org/freedesktop/secrets/aliases/default
/org/freedesktop/secrets/collection/cN
/org/freedesktop/secrets/collection/cN/N
/org/freedesktop/secrets/session/N
/org/freedesktop/secrets/prompt/N
```

The default collection is also available at
`/org/freedesktop/secrets/aliases/default`.

### org.freedesktop.Secret.Service

The service implements:

- `OpenSession`
- `SearchItems`
- `GetSecrets`
- `ReadAlias`
- `SetAlias`
- `CreateCollection`
- `Lock`
- `Unlock`
- `Collections`

`OpenSession` accepts `plain` and
`dh-ietf1024-sha256-aes128-cbc-pkcs7`. A session object belongs to the D-Bus
connection that created it. Another connection cannot use or close it.

`GetSecrets` returns only items that pass their local restrictions and release
policy. Policy evaluation and verification are asynchronous. A pending protected
read does not block unrelated D-Bus or Varlink requests.

`Lock` sets the manual lock state. `Unlock` is refused while the tracked logind
session is locked. Clearing the manual lock returns a Prompt object. Prompt
authorization uses the polkit action
`io.platformd.secret1.unlock-collection`.

### org.freedesktop.Secret.Collection

Collections implement:

- `CreateItem`
- `SearchItems`
- `Delete`
- `Items`
- `Label`
- `Locked`
- `Created`
- `Modified`

The default collection cannot be deleted. Additional collections and their
items are persisted.

### org.freedesktop.Secret.Item

Items implement:

- `GetSecret`
- `SetSecret`
- `Delete`
- `Attributes`
- `Label`
- `Locked`
- `Created`
- `Modified`

The Secret structure has the D-Bus signature `(oayays)`. It contains the
transport session path, algorithm parameters, secret bytes, and content type.

### org.freedesktop.Secret.Prompt

A Prompt belongs to the D-Bus connection that requested it. `Prompt()` starts
authorization without blocking the daemon event loop. `Dismiss()` cancels a
pending authorization. A prompt is canceled and removed when its owner
disconnects.

## Release policy

Items without a `platformd.policy` attribute use the ordinary Secret Service
path and do not require platformd-trustd or platformd-verifyd.

The following `platformd.policy` values are accepted:

| Item value | trustd policy |
| --- | --- |
| `fresh-verification` | `fresh-user-verification` |
| `trusted-platform` | `local-trusted-session` |

For a protected read, the daemon:

1. validates the collection, item, transport session, D-Bus owner, caller UID,
   and item attributes
2. resolves an eligible logind session for the caller
3. asks platformd-trustd to evaluate the mapped policy for that exact session
4. releases the secret when the result is `policy-satisfied`
5. invokes platformd-verifyd only when the reason code is
   `verification-missing` or `verification-stale`
6. evaluates the same trustd policy again after successful verification
7. validates all release conditions again before replying

The selected logind session must belong to the caller UID, be active, local,
unlocked, and use an eligible user session class. The caller process session is
preferred. If that session is not eligible, exactly one eligible session for the
UID must exist. Ambiguous selection fails closed.

The trustd request has a two-second timeout. A verifyd request has a 125-second
timeout. After verifyd reports success, trustd may be queried for up to two
seconds while the verification event is recorded. The complete operation has a
130-second deadline.

The request is canceled if its D-Bus owner disappears. It also fails if the
collection locks, the item is removed or changes policy, the transport session
changes ownership, the login session becomes ineligible, either sibling service
disappears, or a reply is malformed.

platformd-secretd does not create or cache verification freshness. trustd is the
only freshness authority. verifyd performs authentication and reports a
successful verification event to trustd.

For a bulk read containing both item policies, `local-trusted-session` is
evaluated first. It includes the requirements of `fresh-user-verification`, so
a successful result permits both groups of items. Otherwise, the weaker policy
is evaluated separately and may permit only its own items. A positive policy
result is used for the final reply and is not retained across another policy
query or verification request. Each bulk operation requests verification at
most once. On timeout, no protected items are returned.

## Protected mutation

An item carrying any `platformd.*` attribute is protected against mutation.
`SetSecret`, `Attributes` and `Label` changes, `Delete`, replace-on-create, and
collection deletion require the current item policy to be satisfied. Mutation
does not invoke verifyd. A failed or unavailable trustd query denies the mutation.

`platformd.min-grade` accepts:

- `same-user-weak`
- `systemd-unit`
- `sandboxed-app`

The current caller identity source can establish only `same-user-weak`.
Requiring either stronger value therefore denies access.

Unknown policy values, duplicate platformd attributes, and malformed sibling
replies are rejected. Protected reads and mutations fail closed when an
eligible session or required service is unavailable.

## Lock state

The effective collection lock is the logical OR of:

- the `LockedHint` state of the tracked logind session
- the manual lock set by Secret Service `Lock`

A logind `Lock` request also locks the store immediately. An `Unlock` request
does not clear the desktop lock; the tracked session must report
`LockedHint=false`. Invalidation of `LockedHint` treats the session as locked
until the property is reported again.

Locked collections reject item creation, replacement, secret and metadata
changes, item deletion, and collection deletion with
`org.freedesktop.Secret.Error.IsLocked`. This applies independently of optional
item release policies.

A confirmed logind unlock changes only collection lock state. It does not
clear a manual lock, count as user verification, or refresh a trustd policy.

## Storage

The store is located at:

```text
$XDG_DATA_HOME/platformd-secretd/secrets
```

If `XDG_DATA_HOME` is unset, the path is below
`$HOME/.local/share/platformd-secretd`.

The store has mode 0600. Writes use a temporary file and rename. The daemon
serializes and writes the complete new state before accepting a mutation. An
unreadable, malformed, encrypted-without-key, or unsupported store makes the
daemon read-only so the existing file is not replaced.

The optional `vault-key` systemd credential must be a regular file containing
exactly 32 bytes. When present, the serialized payload is encrypted with
AES-256-GCM. Without a configured key, the payload is stored in cleartext.
The deployment must provide protection through an encrypted home or another
storage mechanism when cleartext storage is not acceptable.

The daemon reads the credential from `$CREDENTIALS_DIRECTORY/vault-key`.
An existing credential directory without `vault-key` does not enable encryption.
If the credential is absent, `SECRETD_VAULT_KEY_FILE` can select a key file for
testing. A supplied credential takes precedence over this setting.

An inaccessible credential directory, an unreadable or malformed credential,
or failure to load an explicitly selected key file causes startup to fail.
No store is created or modified in this case.

Plaintext buffers and the vault key are cleansed after use. The key is locked in
memory where supported. The service unit disables core dumps and swap for the
service.

Loss of the vault key makes an encrypted store unrecoverable.

## Varlink interface

The read-only `io.platformd.Secret` interface is served at:

```text
$XDG_RUNTIME_DIR/platformd-secretd/io.platformd.Secret
```

`GetStatus()` returns:

- effective, desktop, and manual lock state
- item count
- store encryption state
- tracked session identifier
- detected home storage type

`ListItems()` returns labels, attributes, and timestamps. It never returns
secret values.

Example:

```sh
varlinkctl call \
  "$XDG_RUNTIME_DIR/platformd-secretd/io.platformd.Secret" \
  io.platformd.Secret.GetStatus '{}'
```

## Limitations

The service does not isolate mutually untrusted processes running under the
same UID. D-Bus peer credentials establish the UID and PID but not a strong
application identity.

Plain Secret Service transport exposes secret bytes on the user bus. Clients
that negotiate the DH transport receive encrypted secret values on the bus, but
the 1024-bit group is fixed by the Secret Service protocol.

Local root and a compromised user session are outside the protection provided
by this service. A manually locked collection uses the desktop polkit agent and
does not provide a trusted display path.
