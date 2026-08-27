/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p4_tp1_s7_260827_155658.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 1;
    BIO *b_enc = NULL, *b_mem_enc = NULL;
    BIO *b_dec = NULL, *b_mem_dec = NULL;
    unsigned char key[32], iv[16];
    const char *plaintext = "The quick brown fox jumps over the lazy dog. "
                             "Testing OpenSSL BIO cipher filters for AES-256-CBC "
                             "round-trip stability and padding logic.";
    int plaintext_len = (int)strlen(plaintext);
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    int cipher_len = 0, decrypted_len = 0;

    /* Setup constant vectors */
    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* --- Encryption Phase --- */
    /* Filter BIO on top of a Memory BIO */
    b_enc = BIO_new(BIO_f_cipher());
    if (b_enc == NULL) { ok = 0; goto err; }

    b_mem_enc = BIO_new(BIO_s_mem());
    if (b_mem_enc == NULL) { ok = 0; goto err; }

    if (!BIO_push(b_enc, b_mem_enc)) { ok = 0; goto err; }

    /* Initialize BIO cipher for encryption (e=1) */
    if (!BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)) {
        ok = 0;
        goto err;
    }

    /* Write plaintext through the cipher BIO into memory */
    int written = BIO_write(b_enc, plaintext, plaintext_len);
    if (written != plaintext_len) { ok = 0; goto err; }

    /* Flush is mandatory to trigger EVP_CipherFinal_ex and push padding to memory BIO */
    if (BIO_flush(b_enc) <= 0) { ok = 0; goto err; }

    /* Retrieve the raw ciphertext from the underlying memory BIO */
    cipher_len = BIO_read(b_mem_enc, ciphertext, sizeof(ciphertext));
    if (cipher_len <= 0) { ok = 0; goto err; }

    /* Basic sanity: Ciphertext should differs from plaintext */
    if (cipher_len == plaintext_len && 
        memcmp(ciphertext, plaintext, plaintext_len) == 0) {
        ok = 0;
        goto err;
    }

    /* --- Decryption Phase --- */
    b_dec = BIO_new(BIO_f_cipher());
    if (b_dec == NULL) { ok = 0; goto err; }

    b_mem_dec = BIO_new(BIO_s_mem());
    if (b_mem_dec == NULL) { ok = 0; goto err; }

    if (!BIO_push(b_dec, b_mem_dec)) { ok = 0; goto err; }

    /* Load the ciphertext into the memory BIO (underlying the decryptor) */
    int stored = BIO_write(b_mem_dec, ciphertext, cipher_len);
    if (stored != cipher_len) { ok = 0; goto err; }

    /* Initialize BIO cipher for decryption (e=0) */
    if (!BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)) {
        ok = 0;
        goto err;
    }

    /* Read through cipher BIO to decrypt */
    decrypted_len = BIO_read(b_dec, decrypted, sizeof(decrypted));
    if (decrypted_len != plaintext_len) {
        ok = 0;
        goto err;
    }

    /* Compare the round-trip result */
    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, decrypted_len)) {
        ok = 0;
        goto err;
    }

    /* Verify the internal decryption status is OK */
    if (!TEST_true((int)BIO_ctrl(b_dec, BIO_C_GET_CIPHER_STATUS, 0, NULL))) {
        ok = 0;
    }

err:
    if (b_enc) BIO_free_all(b_enc);
    if (b_dec) BIO_free_all(b_dec);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
