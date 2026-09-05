#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
    command -v dbus-run-session >/dev/null 2>&1 || exit 77
    exec sh "$(dirname "$0")/test-env.sh" dbus-run-session \
        --config-file="$(dirname "$0")/test-bus.conf" -- sh "$0" --test-inner "$@"
fi
shift

daemon=${1:?usage: test-locking.sh /path/to/platformd-secretd /path/to/test-locking}
client=${2:?usage: test-locking.sh /path/to/platformd-secretd /path/to/test-locking}
daemon_pid=
trap 'test -z "$daemon_pid" || { kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; }' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

"$daemon" &
daemon_pid=$!
i=0
while ! busctl --user status org.freedesktop.secrets >/dev/null 2>&1; do
    kill -0 "$daemon_pid"
    i=$((i + 1))
    [ "$i" -lt 300 ]
done

"$client"
