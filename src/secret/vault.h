/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stddef.h>
#include <stdint.h>

/* Cryptographic primitives for storage and Secret Service transport. */

#define VAULT_KEY_LEN   32u   /* AES-256-GCM vault key */
#define VAULT_NONCE_LEN 12u   /* 96-bit AES-GCM nonce */
#define VAULT_TAG_LEN   16u   /* 128-bit AES-GCM authentication tag */

/* Fill buf with cryptographically secure random bytes. 0 on success, -EIO on failure. */
int vault_random(void *buf, size_t len);

/* Wipe sensitive memory in place (does not free). */
void vault_wipe(void *buf, size_t len);

/* AES-256-GCM seal: generate a fresh nonce, encrypt pt_len bytes of pt into
 * ct_out (which must hold pt_len bytes), and write the authentication tag.
 * Returns 0 on success, negative on failure. */
int vault_seal(const uint8_t key[VAULT_KEY_LEN],
               const uint8_t *pt, size_t pt_len,
               uint8_t nonce_out[VAULT_NONCE_LEN],
               uint8_t *ct_out,
               uint8_t tag_out[VAULT_TAG_LEN]);

/* AES-256-GCM open: verify the tag and decrypt ct_len bytes into pt_out (which
 * must hold ct_len bytes). Returns 0 on success, -EBADMSG if authentication
 * fails (wrong key, wrong nonce, or tampering), negative otherwise. */
int vault_open(const uint8_t key[VAULT_KEY_LEN],
               const uint8_t nonce[VAULT_NONCE_LEN],
               const uint8_t *ct, size_t ct_len,
               const uint8_t tag[VAULT_TAG_LEN],
               uint8_t *pt_out);

/* --- Secret Service DH session transport (dh-ietf1024-sha256-aes128-cbc-pkcs7) --- */

#define VAULT_DH_KEY_LEN 16u   /* AES-128 transport key derived from the DH secret */
#define VAULT_DH_IV_LEN  16u   /* AES-128-CBC IV */

/* 1024-bit MODP DH (RFC 2409 group 2, g=2) + HKDF-SHA256, matching libsecret /
 * gnome-keyring. Given the peer's public key, generate our keypair; output our
 * public key, owned by the caller, and the derived AES-128 transport key.
 * Returns 0, or a negative errno-style code. */
int vault_dh_transport(const uint8_t *peer_pub, size_t peer_len,
                       uint8_t **our_pub, size_t *our_pub_len,
                       uint8_t key_out[VAULT_DH_KEY_LEN]);

#ifdef VAULT_TESTING
int vault_dh_transport_for_test(const uint8_t *peer_pub, size_t peer_len,
                                const uint8_t *private_key, size_t private_key_len,
                                uint8_t **our_pub, size_t *our_pub_len,
                                uint8_t key_out[VAULT_DH_KEY_LEN]);
#endif

/* AES-128-CBC with PKCS7 padding for the transport. Encrypt generates a fresh
 * IV; decrypt validates the padding. Outputs are malloc'd; caller frees.
 * decrypt returns -EBADMSG on a padding/format failure. */
int vault_transport_encrypt(const uint8_t key[VAULT_DH_KEY_LEN],
                            const uint8_t *pt, size_t pt_len,
                            uint8_t iv_out[VAULT_DH_IV_LEN],
                            uint8_t **ct_out, size_t *ct_len);
int vault_transport_decrypt(const uint8_t key[VAULT_DH_KEY_LEN],
                            const uint8_t iv[VAULT_DH_IV_LEN],
                            const uint8_t *ct, size_t ct_len,
                            uint8_t **pt_out, size_t *pt_len);
