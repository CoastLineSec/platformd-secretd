#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
        command -v dbus-run-session >/dev/null 2>&1 || exit 77
        exec sh "$(dirname "$0")/test-env.sh" dbus-run-session \
                --config-file="$(dirname "$0")/test-bus.conf" -- sh "$0" --test-inner "$@"
fi
shift

daemon=${1:?missing daemon}
for tool in busctl varlinkctl secret-tool cmp dd head od; do
        command -v "$tool" >/dev/null 2>&1 || { echo "SKIP: $tool not found"; exit 77; }
done

work=$(mktemp -d)
socket=$XDG_RUNTIME_DIR/platformd-secretd/io.platformd.Secret
pid=

cleanup() {
        if [ -n "$pid" ]; then
                kill "$pid" 2>/dev/null || true
                wait "$pid" 2>/dev/null || true
        fi
        chmod -R u+rwX "$work"
        rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { echo "FAIL: $*" >&2; exit 1; }
status() { varlinkctl --json=short call "$socket" io.platformd.Secret.GetStatus '{}'; }
start() {
        "$daemon" >"$work/daemon.log" 2>&1 &
        pid=$!
        i=0
        until busctl --user --timeout=1 get-property org.freedesktop.secrets \
                        /org/freedesktop/secrets org.freedesktop.Secret.Service Collections >/dev/null 2>&1 &&
                        [ -S "$socket" ]; do
                if ! kill -0 "$pid" 2>/dev/null; then
                        sed -n '1,100p' "$work/daemon.log" >&2
                        fail "daemon exited during startup: $XDG_DATA_HOME"
                fi
                i=$((i + 1))
                [ "$i" -lt 300 ] || fail 'daemon did not start'
                sleep 0.01
        done
}
stop() {
        kill "$pid"
        wait "$pid"
        pid=
}
check_status() {
        result=$(status)
        for pair in "storeLoaded:$1" "storeReadOnly:$2" "storeDegraded:$3" "itemCount:$5" "encrypted:$6"; do
                printf '%s\n' "$result" | grep -Eq "\"${pair%:*}\":${pair#*:}[,}]" ||
                        fail "unexpected $pair in status: $result"
        done
        if [ "$4" = nonzero ]; then
                printf '%s\n' "$result" | grep -Eq '"storeError":[1-9][0-9]*[,}]' ||
                        fail "missing storage error: $result"
        else
                printf '%s\n' "$result" | grep -Eq '"storeError":0[,}]' ||
                        fail "unexpected storage error: $result"
        fi
}
mutate() {
        busctl --user --timeout=2 set-property org.freedesktop.secrets \
                /org/freedesktop/secrets/collection/default \
                org.freedesktop.Secret.Collection Label s changed
}
check_rejected() {
        before=$(status)
        if mutate >/dev/null 2>&1; then
                fail 'read-only store accepted a mutation'
        fi
        [ "$(status)" = "$before" ] || fail 'read-only rejection changed storage status'
}
select_store() {
        XDG_DATA_HOME=$work/$1
        export XDG_DATA_HOME
        mkdir -p "$XDG_DATA_HOME/platformd-secretd"
}

select_store healthy
start
check_status true false false zero 0 false
printf 'synthetic-store-status' | secret-tool store --label=fixture fixture store-status
check_status true false false zero 1 false
stop
cp "$XDG_DATA_HOME/platformd-secretd/secrets" "$work/plaintext"
start
check_status true false false zero 1 false
[ "$(secret-tool lookup fixture store-status)" = synthetic-store-status ] || fail 'store was not loaded'

mv "$XDG_DATA_HOME/platformd-secretd" "$work/saved-directory"
printf 'not-a-directory' >"$XDG_DATA_HOME/platformd-secretd"
if mutate >/dev/null 2>&1; then
        fail 'failed persistence was accepted'
fi
check_status true false true nonzero 1 false
rm "$XDG_DATA_HOME/platformd-secretd"
mv "$work/saved-directory" "$XDG_DATA_HOME/platformd-secretd"
mutate
check_status true false false zero 1 false
stop

for test_case in malformed-header truncated-payload malformed-payload unsupported-cipher; do
        select_store "$test_case"
        case "$test_case" in
                malformed-header) printf 'not-a-store' >"$XDG_DATA_HOME/platformd-secretd/secrets" ;;
                truncated-payload) head -c 20 "$work/plaintext" >"$XDG_DATA_HOME/platformd-secretd/secrets" ;;
                malformed-payload)
                        cp "$work/plaintext" "$XDG_DATA_HOME/platformd-secretd/secrets"
                        printf '\377\377\377\377' | dd of="$XDG_DATA_HOME/platformd-secretd/secrets" bs=1 seek=20 conv=notrunc 2>/dev/null
                        ;;
                unsupported-cipher)
                        cp "$work/plaintext" "$XDG_DATA_HOME/platformd-secretd/secrets"
                        printf '\002' | dd of="$XDG_DATA_HOME/platformd-secretd/secrets" bs=1 seek=12 conv=notrunc 2>/dev/null
                        ;;
        esac
        cp "$XDG_DATA_HOME/platformd-secretd/secrets" "$work/unchanged"
        start
        check_status false true true nonzero 0 false
        check_rejected
        stop
        cmp "$work/unchanged" "$XDG_DATA_HOME/platformd-secretd/secrets" || fail 'invalid store was replaced'
done

select_store unreadable
cp "$work/plaintext" "$XDG_DATA_HOME/platformd-secretd/secrets"
chmod 000 "$XDG_DATA_HOME/platformd-secretd/secrets"
if [ -r "$XDG_DATA_HOME/platformd-secretd/secrets" ]; then
        echo 'SKIP: unreadable store (file permissions are bypassed)'
else
        start
        check_status false true true nonzero 0 false
        check_rejected
        stop
fi
chmod 600 "$XDG_DATA_HOME/platformd-secretd/secrets"
cmp "$work/plaintext" "$XDG_DATA_HOME/platformd-secretd/secrets" || fail 'unreadable store was replaced'

head -c 32 /dev/zero >"$work/synthetic-key"
SECRETD_VAULT_KEY_FILE=$work/synthetic-key
export SECRETD_VAULT_KEY_FILE
select_store migration-failure
cp "$work/plaintext" "$XDG_DATA_HOME/platformd-secretd/secrets"
: >"$XDG_DATA_HOME/platformd-secretd/secrets.lock"
chmod 500 "$XDG_DATA_HOME/platformd-secretd"
if [ -w "$XDG_DATA_HOME/platformd-secretd" ]; then
        echo 'SKIP: failed migration (directory permissions are bypassed)'
else
        start
        check_status true true true nonzero 1 false
        [ "$(secret-tool lookup fixture store-status)" = synthetic-store-status ] || fail 'migration failure lost loaded data'
        check_rejected
        stop
fi
chmod 700 "$XDG_DATA_HOME/platformd-secretd"
cmp "$work/plaintext" "$XDG_DATA_HOME/platformd-secretd/secrets" || fail 'failed migration changed the store'

select_store encrypted
cp "$work/plaintext" "$XDG_DATA_HOME/platformd-secretd/secrets"
start
check_status true false false zero 1 true
stop
cp "$XDG_DATA_HOME/platformd-secretd/secrets" "$work/encrypted-store"
unset SECRETD_VAULT_KEY_FILE
start
check_status false true true nonzero 0 false
check_rejected
stop
cmp "$work/encrypted-store" "$XDG_DATA_HOME/platformd-secretd/secrets" || fail 'missing key changed the store'

SECRETD_VAULT_KEY_FILE=$work/synthetic-key
export SECRETD_VAULT_KEY_FILE
nonce_byte=$(od -An -tu1 -j16 -N1 "$XDG_DATA_HOME/platformd-secretd/secrets")
printf '%b' "\\$(printf '%03o' "$((nonce_byte ^ 255))")" |
        dd of="$XDG_DATA_HOME/platformd-secretd/secrets" bs=1 seek=16 conv=notrunc 2>/dev/null
start
check_status false true true nonzero 0 false
check_rejected
stop

echo 'PASS: storage status distinguishes load failure, read-only migration, write failure, and recovery'
