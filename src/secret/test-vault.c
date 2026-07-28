/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Unit tests for storage and Secret Service transport primitives. */

#include "vault.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures;

#define CHECK(cond, msg)                                        \
        do {                                                    \
                if (cond)                                       \
                        printf("ok   - %s\n", (msg));           \
                else {                                          \
                        printf("FAIL - %s\n", (msg));           \
                        failures++;                             \
                }                                               \
        } while (0)

int main(void) {
        uint8_t key[VAULT_KEY_LEN], wrong_key[VAULT_KEY_LEN];
        uint8_t ct[64], nonce[VAULT_NONCE_LEN], tag[VAULT_TAG_LEN], pt[64];
        const char *msg = "s3cr3t-value-42";
        size_t mlen = strlen(msg);
        int r;

        CHECK(vault_random(key, sizeof key) == 0, "vault key generation succeeds");
        CHECK(vault_random(wrong_key, sizeof wrong_key) == 0, "second key generation succeeds");

        r = vault_seal(key, (const uint8_t *) msg, mlen, nonce, ct, tag);
        CHECK(r == 0, "seal succeeds");
        CHECK(memcmp(ct, msg, mlen) != 0, "ciphertext differs from plaintext");
        r = vault_open(key, nonce, ct, mlen, tag, pt);
        CHECK(r == 0 && memcmp(pt, msg, mlen) == 0, "open recovers the plaintext");

        ct[0] ^= 0x01;
        CHECK(vault_open(key, nonce, ct, mlen, tag, pt) == -EBADMSG, "tampered ciphertext rejected");
        ct[0] ^= 0x01;
        CHECK(vault_open(wrong_key, nonce, ct, mlen, tag, pt) != 0, "wrong key rejected");

        /* DH session transport: AES-128-CBC round-trip. */
        uint8_t tkey[VAULT_DH_KEY_LEN], tiv[VAULT_DH_IV_LEN], *tct = NULL, *tpt = NULL;
        size_t tctlen = 0, tptlen = 0;
        const char *tmsg = "browser-safe-storage-key";
        vault_random(tkey, VAULT_DH_KEY_LEN);
        r = vault_transport_encrypt(tkey, (const uint8_t *) tmsg, strlen(tmsg), tiv, &tct, &tctlen);
        CHECK(r == 0 && tctlen >= strlen(tmsg), "transport encrypt succeeds (PKCS7-padded)");
        r = vault_transport_decrypt(tkey, tiv, tct, tctlen, &tpt, &tptlen);
        CHECK(r == 0 && tptlen == strlen(tmsg) && tpt && memcmp(tpt, tmsg, tptlen) == 0,
              "transport decrypt recovers the plaintext");
        free(tct); free(tpt);

        /* DH agreement runs and yields a key + a public value. */
        uint8_t peer[128], *spub = NULL, dhkey[VAULT_DH_KEY_LEN];
        size_t spublen = 0;
        vault_random(peer, sizeof peer);
        r = vault_dh_transport(peer, sizeof peer, &spub, &spublen, dhkey);
        CHECK(r == 0 && spub && spublen > 0 && spublen <= 128, "dh_transport yields a key + public value");
        free(spub);

        printf("\n%d failure(s)\n", failures);
        return failures == 0 ? 0 : 1;
}
