/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "vault.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>

int vault_random(void *buf, size_t len) {
        return RAND_bytes(buf, (int) len) == 1 ? 0 : -EIO;
}

void vault_wipe(void *buf, size_t len) {
        OPENSSL_cleanse(buf, len);
}

int vault_derive_key(const char *passphrase,
                     const uint8_t salt[VAULT_SALT_LEN],
                     uint8_t key_out[VAULT_KEY_LEN]) {
        EVP_KDF *kdf;
        EVP_KDF_CTX *ctx;
        int r;

        /* Argon2id parameters: 64 MiB memory, 3 passes, single lane. */
        uint32_t memcost = 65536, iter = 3, lanes = 1, threads = 1;

        kdf = EVP_KDF_fetch(NULL, "ARGON2ID", NULL);
        if (!kdf)
                return -ENOTSUP;
        ctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        if (!ctx)
                return -ENOMEM;

        OSSL_PARAM params[7], *p = params;
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                                 (void *) passphrase, strlen(passphrase));
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                                                 (void *) salt, VAULT_SALT_LEN);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads);
        *p = OSSL_PARAM_construct_end();

        r = EVP_KDF_derive(ctx, key_out, VAULT_KEY_LEN, params) == 1 ? 0 : -EIO;
        EVP_KDF_CTX_free(ctx);
        return r;
}

int vault_seal(const uint8_t key[VAULT_KEY_LEN],
               const uint8_t *pt, size_t pt_len,
               uint8_t nonce_out[VAULT_NONCE_LEN],
               uint8_t *ct_out,
               uint8_t tag_out[VAULT_TAG_LEN]) {
        EVP_CIPHER_CTX *ctx;
        int len = 0, r = -EIO;

        if (vault_random(nonce_out, VAULT_NONCE_LEN) < 0)
                return -EIO;
        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
                return -ENOMEM;

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
                goto out;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, VAULT_NONCE_LEN, NULL) != 1)
                goto out;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce_out) != 1)
                goto out;
        if (pt_len > 0 && EVP_EncryptUpdate(ctx, ct_out, &len, pt, (int) pt_len) != 1)
                goto out;
        if (EVP_EncryptFinal_ex(ctx, ct_out + len, &len) != 1)   /* GCM emits no extra bytes */
                goto out;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, VAULT_TAG_LEN, tag_out) != 1)
                goto out;
        r = 0;
out:
        EVP_CIPHER_CTX_free(ctx);
        return r;
}

int vault_open(const uint8_t key[VAULT_KEY_LEN],
               const uint8_t nonce[VAULT_NONCE_LEN],
               const uint8_t *ct, size_t ct_len,
               const uint8_t tag[VAULT_TAG_LEN],
               uint8_t *pt_out) {
        EVP_CIPHER_CTX *ctx;
        int len = 0, r = -EIO;

        ctx = EVP_CIPHER_CTX_new();
        if (!ctx)
                return -ENOMEM;

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
                goto out;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, VAULT_NONCE_LEN, NULL) != 1)
                goto out;
        if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
                goto out;
        if (ct_len > 0 && EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int) ct_len) != 1)
                goto out;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, VAULT_TAG_LEN, (void *) tag) != 1)
                goto out;
        /* DecryptFinal verifies the tag; it fails on wrong key/nonce/tampering. */
        r = EVP_DecryptFinal_ex(ctx, pt_out + len, &len) == 1 ? 0 : -EBADMSG;
out:
        EVP_CIPHER_CTX_free(ctx);
        return r;
}

/* --- Secret Service DH session transport ------------------------------------ */

/* HKDF-SHA256(ikm) with a zero salt and empty info (RFC 5869) — the derivation
 * libsecret / gnome-keyring use for the DH transport. */
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len, uint8_t *out, size_t out_len) {
        static const uint8_t zero_salt[32] = {0};
        EVP_KDF *kdf;
        EVP_KDF_CTX *ctx;
        int r;

        kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
        if (!kdf)
                return -ENOTSUP;
        ctx = EVP_KDF_CTX_new(kdf);
        EVP_KDF_free(kdf);
        if (!ctx)
                return -ENOMEM;

        OSSL_PARAM params[5], *p = params;
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *) "SHA256", 0);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void *) ikm, ikm_len);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (void *) zero_salt, sizeof zero_salt);
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void *) "", 0);
        *p = OSSL_PARAM_construct_end();

        r = EVP_KDF_derive(ctx, out, out_len, params) == 1 ? 0 : -EIO;
        EVP_KDF_CTX_free(ctx);
        return r;
}

/* The 1024-bit MODP group + shared-secret use OpenSSL's legacy DH API (deprecated
 * in 3.x, but the clearest way to pin RFC 2409 group 2). */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
int vault_dh_transport(const uint8_t *peer_pub, size_t peer_len,
                       uint8_t **our_pub, size_t *our_pub_len,
                       uint8_t key_out[VAULT_DH_KEY_LEN]) {
        DH *dh = NULL;
        BIGNUM *p = NULL, *g = NULL, *peer = NULL;
        const BIGNUM *pub = NULL;
        uint8_t *shared = NULL;
        int sz = 0, slen, r = -EIO;

        *our_pub = NULL;

        p = BN_get_rfc2409_prime_1024(NULL);
        g = BN_new();
        if (!p || !g || BN_set_word(g, 2) != 1)
                goto out;
        dh = DH_new();
        if (!dh || DH_set0_pqg(dh, p, NULL, g) != 1)
                goto out;
        p = g = NULL;   /* owned by dh now */
        if (DH_generate_key(dh) != 1)
                goto out;

        peer = BN_bin2bn(peer_pub, (int) peer_len, NULL);
        sz = DH_size(dh);
        if (!peer || sz <= 0 || !(shared = malloc((size_t) sz)))
                goto out;
        /* Minimal big-endian, leading zeros stripped — matches gcrypt USG. */
        slen = DH_compute_key(shared, peer, dh);
        if (slen < 0 || hkdf_sha256(shared, (size_t) slen, key_out, VAULT_DH_KEY_LEN) < 0)
                goto out;

        DH_get0_key(dh, &pub, NULL);
        *our_pub_len = (size_t) BN_num_bytes(pub);
        if (!(*our_pub = malloc(*our_pub_len ? *our_pub_len : 1)))
                goto out;
        BN_bn2bin(pub, *our_pub);
        r = 0;
out:
        if (shared) { vault_wipe(shared, (size_t) sz); free(shared); }
        BN_free(peer);
        BN_free(p);
        BN_free(g);
        DH_free(dh);
        if (r < 0) { free(*our_pub); *our_pub = NULL; }
        return r;
}
#pragma GCC diagnostic pop

int vault_transport_encrypt(const uint8_t key[VAULT_DH_KEY_LEN],
                            const uint8_t *pt, size_t pt_len,
                            uint8_t iv_out[VAULT_DH_IV_LEN],
                            uint8_t **ct_out, size_t *ct_len) {
        EVP_CIPHER_CTX *ctx;
        int len = 0, total = 0, r = -EIO;

        *ct_out = NULL;
        if (vault_random(iv_out, VAULT_DH_IV_LEN) < 0)
                return -EIO;
        if (!(ctx = EVP_CIPHER_CTX_new()))
                return -ENOMEM;
        if (!(*ct_out = malloc(pt_len + VAULT_DH_IV_LEN))) {   /* room for one pad block */
                r = -ENOMEM;
                goto out;
        }
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv_out) != 1)
                goto out;
        if (pt_len > 0 && EVP_EncryptUpdate(ctx, *ct_out, &len, pt, (int) pt_len) != 1)
                goto out;
        total = len;
        if (EVP_EncryptFinal_ex(ctx, *ct_out + total, &len) != 1)   /* PKCS7 */
                goto out;
        *ct_len = (size_t) (total + len);
        r = 0;
out:
        EVP_CIPHER_CTX_free(ctx);
        if (r < 0) { free(*ct_out); *ct_out = NULL; }
        return r;
}

int vault_transport_decrypt(const uint8_t key[VAULT_DH_KEY_LEN],
                            const uint8_t iv[VAULT_DH_IV_LEN],
                            const uint8_t *ct, size_t ct_len,
                            uint8_t **pt_out, size_t *pt_len) {
        EVP_CIPHER_CTX *ctx;
        int len = 0, total = 0, r = -EBADMSG;

        *pt_out = NULL;
        if (!(ctx = EVP_CIPHER_CTX_new()))
                return -ENOMEM;
        if (!(*pt_out = malloc(ct_len ? ct_len : 1))) {
                r = -ENOMEM;
                goto out;
        }
        if (EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1)
                goto out;
        if (ct_len > 0 && EVP_DecryptUpdate(ctx, *pt_out, &len, ct, (int) ct_len) != 1)
                goto out;
        total = len;
        if (EVP_DecryptFinal_ex(ctx, *pt_out + total, &len) != 1)   /* validates PKCS7 */
                goto out;
        *pt_len = (size_t) (total + len);
        r = 0;
out:
        EVP_CIPHER_CTX_free(ctx);
        if (r < 0) { free(*pt_out); *pt_out = NULL; }
        return r;
}
