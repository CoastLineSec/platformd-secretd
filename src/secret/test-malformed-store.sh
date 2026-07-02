#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Parser robustness ("fuzz-lite"): feed truncated, bit-flipped, and hostile
# on-disk store files to platformd-secretd and confirm it never crashes — it
# must ignore a malformed store and still come up (empty or partial). Most
# valuable against an ASan/UBSan build, where a parser memory bug aborts the
# process and is caught here. Isolated on a private bus. Skips (77) without tools.

set -eu

DAEMON="${1:?usage: test-malformed-store.sh /path/to/platformd-secretd}"
for t in dbus-run-session busctl secret-tool dd; do
        command -v "$t" >/dev/null 2>&1 || { echo "SKIP: $t not found"; exit 77; }
done
if [ -z "${PLATFORMD_TEST_INNER:-}" ]; then
        PLATFORMD_TEST_INNER=1 exec dbus-run-session -- sh "$0" "$DAEMON"
fi

NAME=org.freedesktop.secrets
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

# Start the daemon with a given store file; return 0 if it survived (came up, or
# exited cleanly), non-zero only if it was killed by a signal (segv / ASan abort).
survives() {
        rm -rf "$WORK/run"; mkdir -p "$WORK/run/platformd-secretd"
        cp "$1" "$WORK/run/platformd-secretd/secrets"
        XDG_DATA_HOME="$WORK/run" "$DAEMON" >/dev/null 2>&1 &
        pid=$!
        i=0
        while [ $i -lt 100 ]; do
                busctl --user status "$NAME" >/dev/null 2>&1 && break
                kill -0 "$pid" 2>/dev/null || break
                i=$((i + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
                kill -TERM "$pid" 2>/dev/null || true
                wait "$pid" 2>/dev/null || true
                return 0
        fi
        wait "$pid" 2>/dev/null; rc=$?
        [ "$rc" -lt 128 ]   # <128: clean exit; >=128: died on a signal = crash
}

# Seed a valid store on the private bus.
XDG_DATA_HOME="$WORK/seed" "$DAEMON" >/dev/null 2>&1 &
spid=$!
i=0; while [ $i -lt 200 ]; do busctl --user status "$NAME" >/dev/null 2>&1 && break; i=$((i + 1)); done
printf 'seed-secret' | XDG_DATA_HOME="$WORK/seed" secret-tool store --label='seed' a b c d >/dev/null 2>&1 || true
kill -TERM "$spid" 2>/dev/null || true; wait "$spid" 2>/dev/null || true
VALID="$WORK/seed/platformd-secretd/secrets"
[ -f "$VALID" ] || { echo "FAIL: could not seed a valid store"; exit 1; }
SZ=$(wc -c < "$VALID")

n=0; fails=0
check() {
        n=$((n + 1))
        if ! survives "$WORK/m"; then
                echo "  CRASH on: $1"
                fails=$((fails + 1))
        fi
}

# Empty and random inputs.
: > "$WORK/m";                     check "empty file"
head -c 4  /dev/urandom > "$WORK/m"; check "4 random bytes"
head -c 64 /dev/urandom > "$WORK/m"; check "64 random bytes"

# Truncations of the valid store at header/field boundaries.
for off in 4 8 12 16 20 24 32 40 $((SZ - 1)); do
        [ "$off" -gt 0 ] || continue
        head -c "$off" "$VALID" > "$WORK/m"; check "truncated@$off"
done

# Single-byte 0xff corruptions walked across the file.
j=0
while [ "$j" -lt "$SZ" ] && [ "$j" -lt 64 ]; do
        cp "$VALID" "$WORK/m"
        printf '\377' | dd of="$WORK/m" bs=1 seek="$j" count=1 conv=notrunc 2>/dev/null
        check "byte@$j=0xff"
        j=$((j + 3))
done

# Hostile length/count field (offset 16 = payload length for cipher 0).
cp "$VALID" "$WORK/m"
printf '\377\377\377\377' | dd of="$WORK/m" bs=1 seek=16 count=4 conv=notrunc 2>/dev/null
check "huge-length@16"

echo ""
echo "$n malformed inputs tested, $fails crash(es)"
[ "$fails" -eq 0 ] || exit 1
echo "PASS: parser survived all malformed inputs"
