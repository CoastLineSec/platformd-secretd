#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Integration test: run platformd-secretd on a *private* session bus and confirm
# a secret-tool store/lookup round-trip. Isolated via dbus-run-session so it
# never touches the developer's real Secret Service. Skips (exit 77) if the
# required tools are unavailable.

set -eu

DAEMON="${1:?usage: test-integration.sh /path/to/platformd-secretd}"

for tool in dbus-run-session secret-tool busctl; do
        command -v "$tool" >/dev/null 2>&1 || { echo "SKIP: $tool not found"; exit 77; }
done

# Re-exec inside a private session bus.
if [ -z "${PLATFORMD_TEST_INNER:-}" ]; then
        PLATFORMD_TEST_INNER=1 exec dbus-run-session -- sh "$0" "$DAEMON"
fi

XDG_DATA_HOME="$(mktemp -d)"; export XDG_DATA_HOME

"$DAEMON" >/dev/null 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; rm -rf "$XDG_DATA_HOME"' EXIT INT TERM

i=0
while [ "$i" -lt 300 ]; do
        busctl --user status org.freedesktop.secrets >/dev/null 2>&1 && break
        i=$((i + 1))
done

printf 's3cr3t-int' | secret-tool store --label='integration' svc inttest
got="$(secret-tool lookup svc inttest || true)"

if [ "$got" = "s3cr3t-int" ]; then
        echo "PASS: store/lookup round-trip"
else
        echo "FAIL: lookup returned '$got'"
        exit 1
fi
