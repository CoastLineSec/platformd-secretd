#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
    command -v dbus-run-session >/dev/null 2>&1 || exit 77
    exec sh "$(dirname "$0")/test-env.sh" dbus-run-session \
        --config-file="$(dirname "$0")/test-bus.conf" -- sh "$0" --test-inner "$@"
fi
shift

DAEMON="${1:?missing test daemon}"
FAKE="${2:?missing policy service}"
SECRETCTL="${3:?missing secretctl}"

for tool in dbus-run-session secret-tool busctl varlinkctl timeout; do
        command -v "$tool" >/dev/null 2>&1 || {
                echo "SKIP: $tool not found"
                exit 77
        }
done

WORK="$(mktemp -d)"
daemon_pid=
fake_pid=
lookup_pid=
trap 'test -z "$lookup_pid" || kill "$lookup_pid" 2>/dev/null || true
      test -z "$daemon_pid" || kill "$daemon_pid" 2>/dev/null || true
      test -z "$fake_pid" || kill "$fake_pid" 2>/dev/null || true
      test -z "$lookup_pid" || wait "$lookup_pid" 2>/dev/null || true
      test -z "$daemon_pid" || wait "$daemon_pid" 2>/dev/null || true
      test -z "$fake_pid" || wait "$fake_pid" 2>/dev/null || true
      rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_path() {
        path="$1"
        i=0
        while [ ! -S "$path" ] && [ "$i" -lt 500 ]; do
                i=$((i + 1))
                sleep 0.01
        done
        [ -S "$path" ]
}

wait_for_service() {
        i=0
        while ! busctl --user status org.freedesktop.secrets >/dev/null 2>&1; do
                i=$((i + 1))
                [ "$i" -lt 500 ] || return 1
                sleep 0.01
        done
}

stop_case() {
        test -z "$lookup_pid" || {
                kill "$lookup_pid" 2>/dev/null || true
                wait "$lookup_pid" 2>/dev/null || true
                lookup_pid=
        }
        test -z "$daemon_pid" || {
                kill "$daemon_pid" 2>/dev/null || true
                wait "$daemon_pid" 2>/dev/null || true
                daemon_pid=
        }
        test -z "$fake_pid" || {
                kill "$fake_pid" 2>/dev/null || true
                wait "$fake_pid" 2>/dev/null || true
                fake_pid=
        }
}

start_case() {
        mode="$1"
        case_dir="$WORK/$mode-$(date +%s%N)"
        system_address="unix:path=$case_dir/no-system-bus"
        if [ "$mode" = "polkit-delay" ]; then
                system_address="$DBUS_SESSION_BUS_ADDRESS"
        fi
        mkdir -p "$case_dir/runtime" "$case_dir/data"
        "$FAKE" "$case_dir/runtime" "$mode" >/dev/null 2>&1 &
        fake_pid=$!
        if [ "$mode" != "no-trust" ]; then
                wait_for_path "$case_dir/runtime/trust.sock"
                stats_socket="$case_dir/runtime/trust.sock"
        else
                wait_for_path "$case_dir/runtime/verify.sock"
                stats_socket="$case_dir/runtime/verify.sock"
        fi
        if [ "$mode" != "no-verify" ]; then
                wait_for_path "$case_dir/runtime/verify.sock"
        fi
        XDG_DATA_HOME="$case_dir/data" \
        SECRETD_TEST_SESSION_ID=test-session \
        PLATFORMD_TRUST_SOCKET="$case_dir/runtime/trust.sock" \
        PLATFORMD_VERIFY_SOCKET="$case_dir/runtime/verify.sock" \
        DBUS_SYSTEM_BUS_ADDRESS="$system_address" \
                "$DAEMON" >/dev/null 2>&1 &
        daemon_pid=$!
        wait_for_service
}

store_item() {
        name="$1"
        policy="$2"
        value="$3"
        printf '%s' "$value" | secret-tool store --label="$name" scenario "$name" platformd.policy "$policy"
}

lookup_item() {
        secret-tool lookup scenario "$1" 2>/dev/null || true
}

expect_release() {
        mode="$1"
        policy="$2"
        start_case "$mode"
        store_item item "$policy" test-value
        [ "$(lookup_item item)" = "test-value" ] || {
                echo "FAIL: $mode did not release $policy"
                varlinkctl call "$stats_socket" io.platformd.Test.GetStats '{}' || true
                exit 1
        }
        stop_case
}

expect_denial() {
        mode="$1"
        start_case "$mode"
        store_item item fresh-verification test-value
        [ -z "$(lookup_item item)" ] || {
                echo "FAIL: $mode released a denied item"
                exit 1
        }
        stop_case
}

expect_release satisfied fresh-verification
expect_release satisfied trusted-platform
expect_release stale-then-success fresh-verification
expect_release stale-delayed fresh-verification
expect_denial stale-forever
expect_denial verify-decline
expect_denial verify-malformed
expect_denial malformed
expect_denial no-verify
expect_denial no-trust

start_case locked
store_item item fresh-verification test-value
[ -z "$(lookup_item item)" ]
stats="$(varlinkctl call "$stats_socket" io.platformd.Test.GetStats '{}')"
echo "$stats" | grep -Eq '"verifyCalls"[[:space:]]*:[[:space:]]*0'
stop_case

start_case verify-delay
printf 'open-value' | secret-tool store --label=open scenario open
store_item protected fresh-verification protected-value
lookup_item protected >"$case_dir/protected.out" &
lookup_pid=$!
sleep 0.2
[ "$(timeout 1 secret-tool lookup scenario open)" = "open-value" ] || {
        echo "FAIL: a pending verification blocked an unprotected read"
        exit 1
}
wait "$lookup_pid"
lookup_pid=
[ "$(cat "$case_dir/protected.out")" = "protected-value" ]
stop_case

start_case verify-delay
store_item protected fresh-verification protected-value
lookup_item protected >"$case_dir/locked.out" &
lookup_pid=$!
sleep 0.2
"$SECRETCTL" lock >/dev/null
if ! wait "$lookup_pid"; then
        cat "$case_dir/unlock.out"
        echo "FAIL: collection authorization was not accepted"
        exit 1
fi
lookup_pid=
[ ! -s "$case_dir/locked.out" ] || {
        echo "FAIL: a secret was released after the collection locked"
        exit 1
}
stop_case

start_case verify-delay
printf 'open-value' | secret-tool store --label=open scenario open
store_item protected fresh-verification protected-value
lookup_item protected >/dev/null &
lookup_pid=$!
sleep 0.2
kill "$lookup_pid"
wait "$lookup_pid" 2>/dev/null || true
lookup_pid=
[ "$(timeout 1 secret-tool lookup scenario open)" = "open-value" ] || {
        echo "FAIL: client disconnect left the provider unresponsive"
        exit 1
}
stop_case

start_case verify-delay
printf 'open-value' | secret-tool store --label=open scenario open
store_item protected fresh-verification protected-value
lookup_item protected >"$case_dir/disconnected.out" &
lookup_pid=$!
sleep 0.2
kill "$fake_pid"
wait "$fake_pid" 2>/dev/null || true
fake_pid=
wait "$lookup_pid"
lookup_pid=
[ ! -s "$case_dir/disconnected.out" ] || {
        echo "FAIL: a secret was released after a sibling service disappeared"
        exit 1
}
[ "$(timeout 1 secret-tool lookup scenario open)" = "open-value" ] || {
        echo "FAIL: sibling loss left the provider unresponsive"
        exit 1
}
stop_case

start_case polkit-delay
"$SECRETCTL" lock >/dev/null
"$SECRETCTL" unlock >"$case_dir/unlock.out" 2>&1 &
lookup_pid=$!
sleep 0.2
timeout 1 "$SECRETCTL" list >/dev/null || {
        echo "FAIL: collection authorization blocked the event loop"
        exit 1
}
wait "$lookup_pid"
lookup_pid=
grep -q 'default collection unlocked' "$case_dir/unlock.out"
stats="$(varlinkctl call "$stats_socket" io.platformd.Test.GetStats '{}')"
echo "$stats" | grep -Eq '"polkitCalls"[[:space:]]*:[[:space:]]*1'
echo "$stats" | grep -Eq '"trustCalls"[[:space:]]*:[[:space:]]*0'
stop_case

start_case polkit-delay
"$SECRETCTL" lock >/dev/null
"$SECRETCTL" unlock >/dev/null 2>&1 &
lookup_pid=$!
sleep 0.2
kill "$lookup_pid"
wait "$lookup_pid" 2>/dev/null || true
lookup_pid=
i=0
while :; do
        stats="$(varlinkctl call "$stats_socket" io.platformd.Test.GetStats '{}')"
        echo "$stats" | grep -Eq '"cancelCalls"[[:space:]]*:[[:space:]]*1' && break
        i=$((i + 1))
        [ "$i" -lt 100 ] || {
                echo "FAIL: a vanished prompt owner did not cancel authorization"
                exit 1
        }
        sleep 0.01
done
timeout 1 "$SECRETCTL" list >/dev/null || {
        echo "FAIL: canceled collection authorization left the provider unresponsive"
        exit 1
}
stop_case

echo "PASS: trustd policy, verifyd step-up, cancellation, and collection authorization"
