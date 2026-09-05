#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
    command -v dbus-run-session >/dev/null 2>&1 || exit 77
    exec sh "$(dirname "$0")/test-env.sh" dbus-run-session \
        --config-file="$(dirname "$0")/test-bus.conf" -- sh "$0" --test-inner "$@"
fi
shift

DAEMON="${1:?usage: test-integration.sh /path/to/platformd-secretd}"

for tool in dbus-run-session secret-tool busctl; do
        command -v "$tool" >/dev/null 2>&1 || { echo "SKIP: $tool not found"; exit 77; }
done

XDG_DATA_HOME="$(mktemp -d)"; export XDG_DATA_HOME

"$DAEMON" >/dev/null 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true; wait "$PID" 2>/dev/null || true; rm -rf "$XDG_DATA_HOME"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

i=0
while ! busctl --user status org.freedesktop.secrets >/dev/null 2>&1; do
        if ! kill -0 "$PID" 2>/dev/null; then
                wait "$PID" || rc=$?
                echo "FAIL: platformd-secretd exited before claiming its bus name (status ${rc:-0})"
                exit 1
        fi
        if [ "$i" -ge 500 ]; then
                echo "FAIL: platformd-secretd did not claim its bus name"
                exit 1
        fi
        i=$((i + 1))
        sleep 0.01
done

printf 's3cr3t-int' | secret-tool store --label='integration' svc inttest
got="$(secret-tool lookup svc inttest || true)"

if [ "$got" = "s3cr3t-int" ]; then
        echo "PASS: store/lookup round-trip"
else
        echo "FAIL: lookup returned '$got'"
        exit 1
fi

# The unavailable trust authority must prevent both release and policy removal.
printf 'p1atf0rm' | secret-tool store --label='gated' svc gated platformd.policy trusted-platform

# The gated secret is withheld (verdict denied, no trustd).
if [ -n "$(secret-tool lookup svc gated 2>/dev/null || true)" ]; then
        echo "FAIL: gated secret was released without a trusted platform"
        exit 1
fi
echo "PASS: gated secret withheld"

# Find the item's object path and attempt to strip its policy via SetAttributes.
item="$(busctl --user call org.freedesktop.secrets /org/freedesktop/secrets \
        org.freedesktop.Secret.Service SearchItems 'a{ss}' 1 svc gated 2>/dev/null \
        | sed -n 's/.*\(\/org\/freedesktop\/secrets\/[A-Za-z0-9/]*\).*/\1/p' | head -n1)"
if [ -n "$item" ]; then
        if busctl --user set-property org.freedesktop.secrets "$item" \
                org.freedesktop.Secret.Item Attributes 'a{ss}' 1 svc gated >/dev/null 2>&1; then
                echo "FAIL: stripped the policy off a gated item (mutation not gated)"
                exit 1
        fi
        echo "PASS: protected mutation refused"
fi
