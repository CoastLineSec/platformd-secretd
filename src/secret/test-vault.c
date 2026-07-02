/* SPDX-License-Identifier: LGPL-2.1-or-later */
/* Unit tests for the vault crypto primitives (Argon2id + AES-256-GCM). */

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
        uint8_t salt[VAULT_SALT_LEN], salt2[VAULT_SALT_LEN];
        uint8_t k1[VAULT_KEY_LEN], k2[VAULT_KEY_LEN], k3[VAULT_KEY_LEN];
        uint8_t ct[64], nonce[VAULT_NONCE_LEN], tag[VAULT_TAG_LEN], pt[64];
        const char *msg = "s3cr3t-value-42";
        size_t mlen = strlen(msg);
        int r;

        /* Argon2id: deterministic per (passphrase, salt), salt-sensitive. */
        memcpy(salt,  "0123456789abcdef", VAULT_SALT_LEN);
        memcpy(salt2, "fedcba9876543210", VAULT_SALT_LEN);
        r = vault_derive_key("correct horse battery staple", salt, k1);
        CHECK(r == 0, "derive_key succeeds");
        vault_derive_key("correct horse battery staple", salt, k2);
        vault_derive_key("correct horse battery staple", salt2, k3);
        CHECK(memcmp(k1, k2, VAULT_KEY_LEN) == 0, "same passphrase+salt -> same key");
        CHECK(memcmp(k1, k3, VAULT_KEY_LEN) != 0, "different salt -> different key");

        /* AES-256-GCM round-trip. */
        r = vault_seal(k1, (const uint8_t *) msg, mlen, nonce, ct, tag);
        CHECK(r == 0, "seal succeeds");
        CHECK(memcmp(ct, msg, mlen) != 0, "ciphertext differs from plaintext");
        r = vault_open(k1, nonce, ct, mlen, tag, pt);
        CHECK(r == 0 && memcmp(pt, msg, mlen) == 0, "open recovers the plaintext");

        /* Integrity: reject tampering and the wrong key. */
        ct[0] ^= 0x01;
        CHECK(vault_open(k1, nonce, ct, mlen, tag, pt) == -EBADMSG, "tampered ciphertext rejected");
        ct[0] ^= 0x01;
        CHECK(vault_open(k3, nonce, ct, mlen, tag, pt) != 0, "wrong key rejected");

        /* Per-item key wrap/unwrap (the storage key hierarchy). */
        uint8_t ik[VAULT_KEY_LEN], wrapped[VAULT_KEY_LEN],
                wn[VAULT_NONCE_LEN], wt[VAULT_TAG_LEN], uk[VAULT_KEY_LEN];
        CHECK(vault_random(ik, VAULT_KEY_LEN) == 0, "vault_random succeeds");
        r  = vault_seal(k1, ik, VAULT_KEY_LEN, wn, wrapped, wt);
        r |= vault_open(k1, wn, wrapped, VAULT_KEY_LEN, wt, uk);
        CHECK(r == 0 && memcmp(ik, uk, VAULT_KEY_LEN) == 0, "per-item key wrap/unwrap round-trips");

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
