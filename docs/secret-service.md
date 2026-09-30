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
/org/freedesktop/secrets/collection/cN/iID
/org/freedesktop/secrets/session/N
/org/freedesktop/secrets/prompt/N
```

The `default` alias initially names the default collection. Aliases can be
assigned or removed with `SetAlias` and persist across restarts. An alias path
exports the same Collection interface as its canonical target.

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

All collections share one lock state. `Lock` and `Unlock` ignore unknown object
paths, and an empty object list is a no-op. Locking a known collection or item
locks the provider and returns all affected canonical collection and item
paths. Lock changes are signaled on collections, aliases, and items.

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
items are persisted. Collection labels are writable and persistent. Deleted
objects are unregistered and no longer accept requests.

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

The trustd request has a two-second timeout. A verifyd request has a 610-second
timeout. After verifyd reports success, trustd may be queried for up to two
seconds while the verification event is recorded. The complete operation has a
615-second suspend-aware deadline, covering verifyd's configurable maximum
verification interval. The deadline is checked again before releasing protected
items, independently of timer dispatch order.

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
Queries are asynchronous, subject-bound, and limited to two seconds overall.
Repeated policies are evaluated once. Before committing, the daemon checks the
request owner, session, lock state, and store revision again.

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
until the property is reported again. Locking cancels pending policy requests,
verification, and unlock authorization. A known graphical session whose state
cannot be read remains locked. Without a graphical session, manual locking is
available independently of logind.

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

The store has mode 0600. Writes synchronize the temporary file, rename it, then
synchronize the containing directory. The daemon
serializes and writes the complete new state before accepting a mutation. An
unreadable, malformed, encrypted-without-key, or unsupported store makes the
daemon read-only so the existing file is not replaced.
Failure before rename preserves the previous file. Failure to synchronize the
directory after rename leaves durability uncertain; the mutation is not
acknowledged and the service exits for recovery from the visible store.

Version 3 persists item paths, collection labels, and aliases. Version 2 stores
are migrated on load. Item paths in version 2 were not persisted; migration
assigns new stable identifiers. Applications should rediscover items by
attributes. Older package versions cannot read version 3. A failed migration
leaves the service read-only.

The optional `vault-key` systemd credential must be a regular file containing
exactly 32 bytes. When present, the serialized payload is encrypted with
AES-256-GCM. Without a configured key, the payload is stored in cleartext.
An existing plaintext store is migrated before encrypted storage is reported.
`GetStatus.encrypted` describes the successfully persisted file, not merely a
loaded key. An empty provider has no encrypted file until its first write.
The deployment must provide protection through an encrypted home or another
storage mechanism when cleartext storage is not acceptable.

The daemon reads the credential from `$CREDENTIALS_DIRECTORY/vault-key`.
An existing credential directory without `vault-key` does not enable encryption.
If the credential is absent, `SECRETD_VAULT_KEY_FILE` can select a key file for
testing. A supplied credential takes precedence over this setting.

An inaccessible credential directory, an unreadable or malformed credential,
or failure to load an explicitly selected key file causes startup to fail.
No store is created or modified in this case.

Owned plaintext buffers, transport keys, and the vault key are cleansed on
release. Secret-bearing D-Bus messages are marked sensitive. This does not
establish erasure of copies held by callers or other libraries. The key is locked in
memory where supported. The service unit disables core dumps and swap for the
service.

Loss of the vault key makes an encrypted store unrecoverable.

## Resource limits

The provider accepts at most 256 transport sessions and 64 prompts, with limits
of 16 sessions and 4 prompts per connection. Protected reads and mutations each
allow 32 pending requests globally and 4 per connection. Bulk requests contain
at most 4096 paths. Storage permits 65536 items, 4096 additional collections,
4096 aliases, and 4096 attributes per item.

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
