#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eu

if [ "${1:-}" != --test-inner ]; then
    command -v dbus-run-session >/dev/null 2>&1 || exit 77
    exec sh "$(dirname "$0")/test-env.sh" dbus-run-session \
        --config-file="$(dirname "$0")/test-bus.conf" -- sh "$0" --test-inner "$@"
fi
shift

daemon="${1:?usage: test-vault-key.sh /path/to/platformd-secretd}"
for tool in busctl secret-tool head od cmp; do
    command -v "$tool" >/dev/null 2>&1 || { echo "SKIP: $tool not found"; exit 77; }
done

work=$(mktemp -d)
pid=

cleanup() {
    if [ -n "$pid" ]; then
        kill -TERM "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    chmod 700 "$work/credentials/unreadable-directory" 2>/dev/null || true
    rm -rf -- "$work"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

fail() {
    echo "FAIL: $*"
    exit 1
}

start() {
    "$daemon" >"$work/daemon.log" 2>&1 &
    pid=$!
    i=0
    while ! busctl --user --timeout=1 status org.freedesktop.secrets >/dev/null 2>&1; do
        if ! kill -0 "$pid" 2>/dev/null; then
            status=0
            wait "$pid" || status=$?
            pid=
            [ "$status" -eq 1 ] || fail "unexpected startup exit status $status"
            return 1
        fi
        [ "$i" -lt 500 ] || fail "startup did not complete"
        i=$((i + 1))
        sleep 0.01
    done
}

stop() {
    kill -TERM "$pid"
    status=0
    wait "$pid" || status=$?
    pid=
    [ "$status" -eq 0 ] || fail "unexpected shutdown exit status $status"
}

store() {
    printf 'vault-key-test-secret' | secret-tool store --label='vault-key test' test vault-key
}

check_cipher() {
    cipher=$(od -An -tu1 -j12 -N4 "$XDG_DATA_HOME/platformd-secretd/secrets")
    [ "$(printf '%s' "$cipher" | tr -s ' ' | sed 's/^ //')" = "$1 0 0 0" ] ||
        fail "$test_case: unexpected store cipher $cipher"
}

mkdir -p "$work/credentials/empty-directory" "$work/credentials/unrelated" \
    "$work/credentials/unreadable-directory"
printf unrelated >"$work/credentials/unrelated/other-credential"
for size in 0 31 32 33; do
    mkdir "$work/credentials/size-$size"
    head -c "$size" /dev/zero >"$work/credentials/size-$size/vault-key"
done
mkdir "$work/credentials/unreadable" "$work/credentials/directory" \
    "$work/credentials/symlink" "$work/credentials/fifo"
cp "$work/credentials/size-32/vault-key" "$work/credentials/unreadable/vault-key"
chmod 000 "$work/credentials/unreadable/vault-key" "$work/credentials/unreadable-directory"
mkdir "$work/credentials/directory/vault-key"
ln -s "$work/no-key" "$work/credentials/symlink/vault-key"
mkfifo "$work/credentials/fifo/vault-key"

for seed in plaintext encrypted; do
    XDG_DATA_HOME="$work/seed-$seed"
    export XDG_DATA_HOME
    unset CREDENTIALS_DIRECTORY SECRETD_VAULT_KEY_FILE
    if [ "$seed" = encrypted ]; then
        SECRETD_VAULT_KEY_FILE="$work/credentials/size-32/vault-key"
        export SECRETD_VAULT_KEY_FILE
    fi
    start || fail "could not seed $seed store"
    store
    stop
done

n=0
for source in none empty-directory unrelated missing-directory unreadable-directory \
    credential-0 credential-31 credential-32 credential-33 credential-unreadable \
    credential-directory credential-symlink credential-fifo explicit-missing \
    explicit-0 explicit-31 explicit-32 explicit-33 explicit-unreadable \
    explicit-directory explicit-symlink explicit-fifo fallback precedence invalid-precedence; do
    if { [ "$source" = credential-unreadable ] || [ "$source" = explicit-unreadable ]; } && \
        [ -r "$work/credentials/unreadable/vault-key" ]; then
        echo "SKIP: $source (file permissions are bypassed)"
        continue
    fi
    if [ "$source" = unreadable-directory ] && [ -r "$work/credentials/unreadable-directory" ]; then
        echo "SKIP: $source (directory permissions are bypassed)"
        continue
    fi

    unset CREDENTIALS_DIRECTORY SECRETD_VAULT_KEY_FILE
    expected=invalid
    case "$source" in
        none) expected=plaintext ;;
        empty-directory|unrelated)
            CREDENTIALS_DIRECTORY="$work/credentials/$source"
            expected=plaintext
            ;;
        missing-directory|unreadable-directory)
            CREDENTIALS_DIRECTORY="$work/credentials/$source"
            ;;
        credential-0|credential-31|credential-32|credential-33)
            CREDENTIALS_DIRECTORY="$work/credentials/size-${source#credential-}"
            [ "$source" != credential-32 ] || expected=encrypted
            ;;
        credential-*) CREDENTIALS_DIRECTORY="$work/credentials/${source#credential-}" ;;
        explicit-0|explicit-31|explicit-32|explicit-33)
            SECRETD_VAULT_KEY_FILE="$work/credentials/size-${source#explicit-}/vault-key"
            [ "$source" != explicit-32 ] || expected=encrypted
            ;;
        explicit-*) SECRETD_VAULT_KEY_FILE="$work/credentials/${source#explicit-}/vault-key" ;;
        fallback)
            CREDENTIALS_DIRECTORY="$work/credentials/unrelated"
            SECRETD_VAULT_KEY_FILE="$work/credentials/size-32/vault-key"
            expected=encrypted
            ;;
        precedence)
            CREDENTIALS_DIRECTORY="$work/credentials/size-32"
            SECRETD_VAULT_KEY_FILE="$work/no-key"
            expected=encrypted
            ;;
        invalid-precedence)
            CREDENTIALS_DIRECTORY="$work/credentials/size-31"
            SECRETD_VAULT_KEY_FILE="$work/credentials/size-32/vault-key"
            ;;
    esac
    export CREDENTIALS_DIRECTORY SECRETD_VAULT_KEY_FILE

    for initial in new plaintext encrypted; do
        test_case="$source/$initial"
        XDG_DATA_HOME="$work/case-$source-$initial"
        export XDG_DATA_HOME
        if [ "$initial" != new ]; then
            mkdir -p "$XDG_DATA_HOME/platformd-secretd"
            cp "$work/seed-$initial/platformd-secretd/secrets" "$XDG_DATA_HOME/platformd-secretd/secrets"
        fi

        if [ "$expected" = invalid ]; then
            if start; then
                fail "$test_case: invalid key was accepted"
            fi
            [ ! -e "$XDG_DATA_HOME/platformd-secretd/secrets" ] || \
                { [ "$initial" != new ] && cmp "$work/seed-$initial/platformd-secretd/secrets" \
                    "$XDG_DATA_HOME/platformd-secretd/secrets"; } ||
                fail "$test_case: startup changed the store"
        else
            start || fail "$test_case: valid configuration was rejected"
            if [ "$initial" = encrypted ] && [ "$expected" = plaintext ]; then
                if store >/dev/null 2>&1; then
                    fail "$test_case: encrypted store was writable without a key"
                fi
                cmp "$work/seed-encrypted/platformd-secretd/secrets" \
                    "$XDG_DATA_HOME/platformd-secretd/secrets" || fail "$test_case: encrypted store changed"
            else
                if [ "$initial" != new ]; then
                    [ "$(secret-tool lookup test vault-key)" = vault-key-test-secret ] ||
                        fail "$test_case: existing secret was not restored"
                fi
                store
                [ "$(secret-tool lookup test vault-key)" = vault-key-test-secret ] ||
                    fail "$test_case: secret round-trip failed"
                if [ "$expected" = encrypted ]; then
                    check_cipher 1
                else
                    check_cipher 0
                fi
            fi
            stop
        fi
        n=$((n + 1))
    done
done

echo "PASS: $n vault-key configurations preserved storage guarantees"
