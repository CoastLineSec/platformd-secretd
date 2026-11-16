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
home_service=$2
daemon_pid=
home_pid=
socket=$XDG_RUNTIME_DIR/platformd-secretd/io.platformd.Secret
export DBUS_SYSTEM_BUS_ADDRESS="$DBUS_SESSION_BUS_ADDRESS"

cleanup() {
        if [ -n "$daemon_pid" ]; then
                kill "$daemon_pid" 2>/dev/null || :
        fi
        if [ -n "$home_pid" ]; then
                kill "$home_pid" 2>/dev/null || :
        fi
        if [ -n "$daemon_pid" ]; then
                wait "$daemon_pid" || :
        fi
        if [ -n "$home_pid" ]; then
                wait "$home_pid" || :
        fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_message() {
        for i in $(seq 1 500); do
                if grep -q "$1" "$TMPDIR/home.log"; then
                        return 0
                fi
                [ "$i" -lt 500 ] || break
                sleep 0.01
        done
        echo "Missing home service marker: $1" >&2
        return 1
}

status() {
        timeout 1 varlinkctl --json=short call "$socket" io.platformd.Secret.GetStatus '{}'
}

for mode in hold delayed malformed disconnect valid missing; do
        if [ "$mode" != missing ]; then
                "$home_service" "$mode" > "$TMPDIR/home.log" &
                home_pid=$!
                wait_message ready
        fi
        "$daemon" &
        daemon_pid=$!
        if [ "$mode" != missing ]; then
                wait_message received
        else
                for i in $(seq 1 100); do
                        if busctl --user status org.freedesktop.secrets >/dev/null 2>&1; then
                                break
                        fi
                        [ "$i" -lt 100 ] || exit 1
                        sleep 0.01
                done
        fi
        timeout 1 busctl --user get-property org.freedesktop.secrets /org/freedesktop/secrets \
                org.freedesktop.Secret.Service Collections >/dev/null
        if [ "$mode" = delayed ]; then
                status | grep -q '"homeStorage":""'
                wait_message replied
                sleep 0.1
        fi
        if [ "$mode" = valid ]; then
                wait_message replied
                for i in $(seq 1 100); do
                        if status | grep -q '"homeStorage":"luks"'; then
                                break
                        fi
                        [ "$i" -lt 100 ] || exit 1
                        sleep 0.01
                done
                status | grep -q '"homeStorage":"luks"'
        else
                status | grep -q '"homeStorage":""'
        fi
        kill "$daemon_pid"
        wait "$daemon_pid"
        daemon_pid=
        if [ -n "$home_pid" ]; then
                kill "$home_pid" 2>/dev/null || :
                wait "$home_pid"
                home_pid=
        fi
done

echo 'OK: optional home metadata is asynchronous, bounded, and canceled on shutdown'
