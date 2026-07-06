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

# --- A1: protected mutation is gated ----------------------------------------
# Store an item that requires the trusted-platform verdict. With no
# platformd-trustd reachable here, that verdict is not satisfied, so the item's
# secret must not be released — and, the point of this check, its protected state
# must not be mutable either (SetAttributes could otherwise strip the policy and
# unlock a read). Point both the trust and verify sockets at dead paths so the
# verdict is denied and the step-up fails fast without a real reader prompt.
export PLATFORMD_TRUST_SOCKET="$XDG_DATA_HOME/no-trustd.sock"
export PLATFORMD_VERIFY_SOCKET="$XDG_DATA_HOME/no-verifyd.sock"
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
