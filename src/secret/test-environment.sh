#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
    exec sh "$(dirname "$0")/test-env.sh" sh "$0" --test-inner "$@"
fi
shift

test_scripts=$(dirname "$0")

if [ "${1:-}" = --check ]; then
    if env | grep -E '^(RUNTIME_DIRECTORY|STATE_DIRECTORY|CACHE_DIRECTORY|LOGS_DIRECTORY|CONFIGURATION_DIRECTORY|CREDENTIALS_DIRECTORY|ENCRYPTED_CREDENTIALS_DIRECTORY|SECRETD_VAULT_KEY_FILE|NOTIFY_SOCKET|WATCHDOG_USEC|WATCHDOG_PID|LISTEN_PID|LISTEN_FDS|LISTEN_FDNAMES|PLATFORMD_TEST_INNER|SECRETD_TEST_SESSION_ID|XDG_SESSION_ID)=' >/dev/null; then
        echo 'FAIL: inherited service environment was retained' >&2
        exit 1
    fi
    test_root=${XDG_RUNTIME_DIR%/runtime}
    case "$test_root" in
        /tmp/platformd-test.??????) ;;
        *) exit 1 ;;
    esac
    test "$XDG_DATA_HOME" = "$test_root/data"
    test "$XDG_CONFIG_HOME" = "$test_root/config"
    test "$XDG_CACHE_HOME" = "$test_root/cache"
    test "$XDG_STATE_HOME" = "$test_root/state"
    test "$TMPDIR" = "$test_root/tmp"
    test "$DBUS_SYSTEM_BUS_ADDRESS" = "unix:path=$test_root/no-system-bus"
    test "$DBUS_SESSION_BUS_ADDRESS" = "unix:path=$test_root/no-session-bus"
    test "$PLATFORMD_TRUST_SOCKET" = "$test_root/no-trustd"
    test "$PLATFORMD_VERIFY_SOCKET" = "$test_root/no-verifyd"
    test "$PLATFORMD_ASK_PASSWORD_SOCKET" = "$test_root/no-ask-password"
    test "$PLATFORMD_VERIFY_PAM_CONFDIR" = "$test_root/no-pam"
    test "$TSS2_TCTI" = "device:$test_root/no-tpm"
    exit 0
fi

if [ "${1:-}" = --check-bus ]; then
    services=$(busctl --user --no-pager call org.freedesktop.DBus /org/freedesktop/DBus \
        org.freedesktop.DBus ListActivatableNames)
    test "$services" = 'as 1 "org.freedesktop.DBus"'
    exit 0
fi

guard=${1:?missing socket guard}
daemon=${2:?missing daemon}
test_daemon=${3:?missing policy test daemon}
policy_service=${4:?missing policy test service}
secretctl=${5:?missing client}
security_test=${6:?missing security test}

"$guard" sh "$test_scripts/test-env.sh" sh "$0" --test-inner --check
"$guard" sh "$test_scripts/test-integration.sh" "$daemon"
"$guard" sh "$test_scripts/test-security.sh" "$daemon" "$security_test"
"$guard" sh "$test_scripts/test-malformed-store.sh" "$daemon"
"$guard" sh "$test_scripts/test-policy.sh" "$test_daemon" "$policy_service" "$secretctl"
sh "$test_scripts/test-env.sh" dbus-run-session \
    --config-file="$test_scripts/test-bus.conf" -- sh "$0" --test-inner --check-bus

echo 'PASS: inherited sockets and credentials are isolated'
