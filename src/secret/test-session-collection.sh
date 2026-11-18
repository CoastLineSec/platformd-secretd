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
client=$2
pid=
service=org.freedesktop.secrets
root=/org/freedesktop/secrets
collection=$root/collection/session
store=$XDG_DATA_HOME/platformd-secretd/secrets
export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"
export SECRETD_TEST_LOGIN_FILE="$XDG_RUNTIME_DIR/login"

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
start() {
        "$daemon" &
        pid=$!
        i=0
        until call ReadAlias s session >/dev/null 2>&1; do
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

printf 'first\n' > "$SECRETD_TEST_LOGIN_FILE"
start
[ "$(call ReadAlias s session)" = "o \"$collection\"" ] || fail 'session alias is missing'
"$client" store session volatile.example.invalid
"$client" lookup session volatile.example.invalid
[ ! -e "$store" ] || fail 'volatile mutation wrote the store'
busctl --user set-property "$service" "$collection" org.freedesktop.Secret.Collection Label s volatile-collection
call SetAlias so volatile-alias "$collection" >/dev/null
[ ! -e "$store" ] || fail 'volatile metadata wrote the store'
if call SetAlias so session "$root/collection/default" >/dev/null 2>&1; then
        fail 'session alias was redirected to persistent storage'
fi
"$client" store default persistent.example.invalid
if grep -a -q -e volatile.example.invalid -e volatile-collection -e volatile-alias "$store"; then
        fail 'volatile metadata was serialized'
fi
before=$(sha256sum "$store")
"$client" store session volatile.example.invalid
[ "$(sha256sum "$store")" = "$before" ] || fail 'volatile replacement changed the store'
stop
start
"$client" missing session volatile.example.invalid
"$client" lookup default persistent.example.invalid
[ "$(call ReadAlias s volatile-alias)" = 'o "/"' ] || fail 'volatile alias survived restart'
"$client" store session volatile.example.invalid
printf 'second\n' > "$SECRETD_TEST_LOGIN_FILE"
"$client" missing session volatile.example.invalid
"$client" store session volatile.example.invalid
printf 'manager\n' > "$SECRETD_TEST_LOGIN_FILE"
"$client" missing session volatile.example.invalid
[ "$(call Unlock ao 1 "$collection")" = 'aoo 0 "/"' ] || fail 'unavailable session collection reported unlocked'
if "$client" store session volatile.example.invalid >/dev/null 2>&1; then
        fail 'lingering manager accepted a session secret'
fi
"$client" lookup default persistent.example.invalid
printf 'closing\n' > "$SECRETD_TEST_LOGIN_FILE"
if "$client" store session volatile.example.invalid >/dev/null 2>&1; then
        fail 'closing session accepted a session secret'
fi
printf 'third\n' > "$SECRETD_TEST_LOGIN_FILE"
"$client" store session volatile.example.invalid
printf 'error\n' > "$SECRETD_TEST_LOGIN_FILE"
"$client" missing session volatile.example.invalid
"$client" lookup default persistent.example.invalid
printf 'fourth\n' > "$SECRETD_TEST_LOGIN_FILE"
"$client" store session volatile.example.invalid
"$client" clear session volatile.example.invalid
"$client" missing session volatile.example.invalid
stop
printf 'invalid-store' > "$store"
before=$(sha256sum "$store")
start
"$client" store session volatile.example.invalid
"$client" lookup session volatile.example.invalid
"$client" clear session volatile.example.invalid
if "$client" store default persistent.example.invalid >/dev/null 2>&1; then
        fail 'read-only persistent store accepted a mutation'
fi
[ "$(sha256sum "$store")" = "$before" ] || fail 'volatile mutation replaced the malformed store'
stop
echo 'PASS: libsecret session storage, restart, logout, linger, and persistence exclusion'
