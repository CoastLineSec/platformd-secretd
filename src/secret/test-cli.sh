#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu
if [ "${1:-}" != --test-inner ]; then
        test_scripts=$(dirname "$0")
        exec sh "$test_scripts/test-env.sh" dbus-run-session \
                --config-file="$test_scripts/test-bus.conf" -- sh "$0" --test-inner "$@"
fi
shift
client=$1
service=$2
pid=
cleanup() {
        if [ -n "$pid" ]; then
                kill "$pid" 2>/dev/null || :
                wait "$pid" || :
        fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for mode in empty other wrong-state good state-error prompt-empty prompt-other \
            prompt-wrong-state prompt-dismissed prompt-invalid prompt-good; do
        "$service" "$mode" > "$TMPDIR/service.log" &
        pid=$!
        for i in $(seq 1 100); do
                if grep -q ready "$TMPDIR/service.log"; then
                        break
                fi
                [ "$i" -lt 100 ] || exit 1
                sleep 0.01
        done
        for verb in lock unlock; do
                result=0
                timeout 3 "$client" "$verb" > "$TMPDIR/output" 2> "$TMPDIR/error" || result=$?
                case "$mode" in
                        good|prompt-good)
                                [ "$result" -eq 0 ]
                                grep -q "^default collection ${verb}ed$" "$TMPDIR/output"
                                ;;
                        *)
                                [ "$result" -eq 1 ]
                                [ ! -s "$TMPDIR/output" ]
                                [ -s "$TMPDIR/error" ]
                                ;;
                esac
        done
        kill "$pid"
        wait "$pid"
        pid=
done
echo 'OK: lock commands validate handled objects, prompt results, and effective state'
