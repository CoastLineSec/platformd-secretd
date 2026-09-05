#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
    command -v dbus-run-session >/dev/null 2>&1 || exit 77
    exec sh "$(dirname "$0")/test-env.sh" dbus-run-session \
        --config-file="$(dirname "$0")/test-bus.conf" -- sh "$0" --test-inner "$@"
fi
shift

daemon=${1:?missing test daemon}
fake=${2:?missing policy service}
client=${3:?missing client}
work=$(mktemp -d)
daemon_pid=
fake_pid=

stop_case() {
    for child in "$daemon_pid" "$fake_pid"; do
        test -z "$child" || kill "$child" 2>/dev/null || true
    done
    for child in "$daemon_pid" "$fake_pid"; do
        test -z "$child" || wait "$child" 2>/dev/null || true
    done
    daemon_pid=
    fake_pid=
}

trap 'stop_case; rm -rf "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for order in forward reverse; do
    for mode in bulk-expiry satisfied bulk-fresh-only verify-decline bulk-malformed \
        verify-delay verify-delay-decline; do
        case_dir="$work/$order-$mode"
        mkdir -p "$case_dir/runtime" "$case_dir/data"
        "$fake" "$case_dir/runtime" "$mode" &
        fake_pid=$!
        i=0
        while [ ! -S "$case_dir/runtime/trust.sock" ]; do
            kill -0 "$fake_pid"
            i=$((i + 1))
            test "$i" -lt 500
            sleep 0.01
        done
        XDG_DATA_HOME="$case_dir/data" \
        SECRETD_TEST_SESSION_ID=test-session \
        PLATFORMD_TRUST_SOCKET="$case_dir/runtime/trust.sock" \
        PLATFORMD_VERIFY_SOCKET="$case_dir/runtime/verify.sock" \
            "$daemon" &
        daemon_pid=$!
        i=0
        while ! busctl --user status org.freedesktop.secrets >/dev/null 2>&1; do
            kill -0 "$daemon_pid"
            i=$((i + 1))
            test "$i" -lt 500
            sleep 0.01
        done
        case "$mode" in
            satisfied) expected=both; trust_calls=1; verify_calls=0 ;;
            verify-delay) expected=both; trust_calls=2; verify_calls=1 ;;
            bulk-fresh-only|bulk-malformed) expected=fresh; trust_calls=2; verify_calls=0 ;;
            bulk-expiry|verify-decline|verify-delay-decline)
                expected=none; trust_calls=2; verify_calls=1 ;;
        esac
        "$client" bulk "$expected" "$order"
        stats=$(varlinkctl call "$case_dir/runtime/trust.sock" io.platformd.Test.GetStats '{}')
        if ! printf '%s\n' "$stats" | grep -F "\"trustCalls\":$trust_calls," >/dev/null ||
           ! printf '%s\n' "$stats" | grep -F "\"verifyCalls\":$verify_calls," >/dev/null; then
            printf 'FAIL: unexpected calls for %s (%s): %s\n' "$mode" "$order" "$stats" >&2
            exit 1
        fi
        stop_case
    done
done

echo 'PASS: bulk reads use a final policy decision without retaining earlier success'
