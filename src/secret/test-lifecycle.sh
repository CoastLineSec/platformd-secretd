#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
        test_scripts=$(dirname "$0")
        exec sh "$test_scripts/test-env.sh" dbus-run-session \
                --config-file="$test_scripts/test-bus.conf" -- sh "$0" --test-inner "$@"
fi
shift
daemon=$1
pid=
service=org.freedesktop.secrets
root=/org/freedesktop/secrets
default=$root/collection/default
socket=$XDG_RUNTIME_DIR/platformd-secretd/io.platformd.Secret
store=$XDG_DATA_HOME/platformd-secretd/secrets

cleanup() {
        if [ -n "$pid" ]; then
                kill "$pid" 2>/dev/null || :
                wait "$pid" || :
        fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
call() { busctl --user call "$service" "$root" org.freedesktop.Secret.Service "$@"; }
property() { busctl --user get-property "$service" "$1" "org.freedesktop.Secret.$2" "$3"; }
path_for() { call SearchItems 'a{ss}' 1 fixture "$1" | sed -n 's/^[^"]*"\([^"]*\)".*/\1/p'; }
start() {
        "$daemon" &
        pid=$!
        i=0
        until property "$root" Service Collections >/dev/null 2>&1 && [ -S "$socket" ]; do
                kill -0 "$pid"
                i=$((i + 1))
                [ "$i" -lt 200 ] || fail 'daemon did not start'
                sleep 0.01
        done
}
stop() {
        kill "$pid"
        wait "$pid"
        pid=
}

start
varlinkctl info "$socket" | grep -q platformd-secretd
normalize_idl() {
        awk '
                { sub(/#.*/, "") }
                /^[[:space:]]*(interface|type|method|error)[[:space:]]/ { if (s != "") print s; s = "" }
                { gsub(/[[:space:]]/, ""); s = s $0 }
                END { if (s != "") print s }
        ' | sort
}
published=$(varlinkctl introspect "$socket" io.platformd.Secret | normalize_idl)
expected=$(normalize_idl < "$(dirname "$0")/io.platformd.Secret.varlink")
[ "$published" = "$expected" ]
timeout 1 "$daemon" --help | grep -q platformd-secretd
timeout 1 "$daemon" --version | grep -q platformd-secretd
if timeout 1 "$daemon" --invalid-option >/dev/null 2>&1; then
        fail 'invalid option was accepted'
fi
printf 'synthetic-first' | secret-tool store --label=first fixture first
printf 'synthetic-second' | secret-tool store --label=second fixture second
first=$(path_for first)
second=$(path_for second)
[ -n "$first" ] && [ -n "$second" ] && [ "$first" != "$second" ] || fail 'item paths are not distinct'
collection=$(call CreateCollection 'a{sv}s' 1 org.freedesktop.Secret.Collection.Label s fixture fixture |
        sed -n 's/^[^"]*"\([^"]*\)".*/\1/p')
[ "$(call ReadAlias s fixture)" = "o \"$collection\"" ] || fail 'alias was not created'
busctl --user set-property "$service" "$collection" org.freedesktop.Secret.Collection Label s changed
busctl --user set-property "$service" "$default" org.freedesktop.Secret.Collection Label s primary
call Lock ao 0 >/dev/null
[ "$(property "$default" Collection Locked)" = 'b false' ] || fail 'empty Lock changed state'
call Lock ao 1 /org/freedesktop/secrets/collection/missing >/dev/null
[ "$(property "$default" Collection Locked)" = 'b false' ] || fail 'unknown object Lock changed state'

inode=$(stat -c %i "$socket")
if "$daemon"; then
        fail 'duplicate daemon was accepted'
fi
[ "$(stat -c %i "$socket")" = "$inode" ] || fail 'duplicate daemon replaced the socket'
varlinkctl call "$socket" io.platformd.Secret.GetStatus '{}' >/dev/null

stop
openssl rand -out "$XDG_RUNTIME_DIR/vault-key" 32
export SECRETD_VAULT_KEY_FILE="$XDG_RUNTIME_DIR/vault-key"
start
[ "$(path_for first)" = "$first" ] || fail 'first item changed path'
[ "$(path_for second)" = "$second" ] || fail 'second item changed path'
[ "$(property "$collection" Collection Label)" = 's "changed"' ] || fail 'collection label was not persisted'
[ "$(property "$default" Collection Label)" = 's "primary"' ] || fail 'default label was not persisted'
[ "$(call ReadAlias s fixture)" = "o \"$collection\"" ] || fail 'alias was not persisted'
varlinkctl --json=short call "$socket" io.platformd.Secret.GetStatus '{}' |
        grep -q '"encrypted":true' || fail 'migrated store is not reported encrypted'
[ "$(od -An -tu4 -j12 -N4 "$store" | tr -d ' ')" = 1 ] || fail 'store remained plaintext'
if grep -a -q synthetic-first "$store"; then
        fail 'plaintext secret survived migration'
fi
new_collection=$(call CreateCollection 'a{sv}s' 1 org.freedesktop.Secret.Collection.Label s next '' |
        sed -n 's/^[^"]*"\([^"]*\)".*/\1/p')
[ "$new_collection" != "$collection" ] || fail 'collection identifier was reused'
busctl --user call "$service" "$second" org.freedesktop.Secret.Item Delete >/dev/null
if busctl --user set-property "$service" "$second" org.freedesktop.Secret.Item Label s removed 2>/dev/null; then
        fail 'deleted item accepted a mutation'
fi
if property "$second" Item Label >/dev/null 2>&1; then
        fail 'deleted item remained registered'
fi
call SetAlias so fixture / >/dev/null
[ "$(call ReadAlias s fixture)" = 'o "/"' ] || fail 'alias removal failed'
stop
start
[ "$(path_for first)" = "$first" ] || fail 'item path changed on second restart'
[ -z "$(path_for second)" ] || fail 'deleted item returned after restart'
[ "$(call ReadAlias s fixture)" = 'o "/"' ] || fail 'removed alias returned after restart'
call Lock ao 1 "$collection" >/dev/null
for path in "$default" "$collection" "$new_collection"; do
        [ "$(property "$path" Collection Locked)" = 'b true' ] || fail 'shared lock state differs between collections'
done
[ "$(property "$first" Item Locked)" = 'b true' ] || fail 'shared lock did not cover the item'
stop
echo 'OK: persistent identities, aliases, encryption migration, deletion, and exclusive ownership'
