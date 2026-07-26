#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

DAEMON="${1:?usage: test-security.sh /path/to/platformd-secretd /path/to/test-security}"
CLIENT="${2:?usage: test-security.sh /path/to/platformd-secretd /path/to/test-security}"

for tool in dbus-run-session busctl; do
        command -v "$tool" >/dev/null 2>&1 || {
                echo "SKIP: $tool not found"
                exit 77
        }
done

if [ -z "${PLATFORMD_TEST_INNER:-}" ]; then
        PLATFORMD_TEST_INNER=1 exec dbus-run-session -- sh "$0" "$DAEMON" "$CLIENT"
fi

WORK="$(mktemp -d)"
PID=
trap 'test -z "$PID" || kill "$PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT INT TERM

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
printf 'not-a-directory' > "$WORK/unwritable/platformd-secretd"
XDG_DATA_HOME="$WORK/unwritable" "$DAEMON" >/dev/null 2>&1 &
PID=$!
wait_for_service
"$CLIENT" persistence

echo "PASS: storage failures are returned to callers"
