#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
    command -v dbus-run-session >/dev/null 2>&1 || exit 77
    exec sh "$(dirname "$0")/test-env.sh" dbus-run-session \
        --config-file="$(dirname "$0")/test-bus.conf" -- sh "$0" --test-inner "$@"
fi
shift

DAEMON="${1:?usage: test-security.sh /path/to/platformd-secretd /path/to/test-security}"
CLIENT="${2:?usage: test-security.sh /path/to/platformd-secretd /path/to/test-security}"

for tool in dbus-run-session busctl; do
        command -v "$tool" >/dev/null 2>&1 || {
                echo "SKIP: $tool not found"
                exit 77
        }
done

WORK="$(mktemp -d)"
PID=
trap 'test -z "$PID" || { kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; }; rm -rf "$WORK"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_service() {
        i=0
        while [ "$i" -lt 300 ]; do
                busctl --user status org.freedesktop.secrets >/dev/null 2>&1 && return 0
                i=$((i + 1))
        done
        return 1
}

XDG_DATA_HOME="$WORK/normal" "$DAEMON" >/dev/null 2>&1 &
PID=$!
wait_for_service
"$CLIENT"
kill "$PID"
wait "$PID" 2>/dev/null || true
PID=

mkdir -p "$WORK/unwritable"
XDG_DATA_HOME="$WORK/unwritable" "$DAEMON" >/dev/null 2>&1 &
PID=$!
wait_for_service
busctl --user get-property org.freedesktop.secrets /org/freedesktop/secrets \
        org.freedesktop.Secret.Service Collections >/dev/null
mv "$WORK/unwritable/platformd-secretd" "$WORK/blocked-store"
printf 'not-a-directory' > "$WORK/unwritable/platformd-secretd"
"$CLIENT" persistence

echo "PASS: storage failures are returned to callers"
