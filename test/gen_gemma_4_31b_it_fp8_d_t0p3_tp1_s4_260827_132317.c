/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p3_tp1_s4_260827_132317.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                              0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                              0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0;
    int dec_len = 0;
    BIO *b_mem = NULL, *b_cipher = NULL;
    BIO *b_mem_dec = NULL, *b_cipher_dec = NULL;

    /* --- Encryption Path --- */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_cipher = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_cipher, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_cipher, plaintext, pt_len) == pt_len))
        goto err;

    /* Finalize encryption (padding) */
    if (!TEST_true(BIO_ctrl(b_cipher, BIO_CTRL_FLUSH, 0, NULL) == 1))
        goto err;

    /* Extract ciphertext from memory BIO */
    ct_len = BIO_read(b_mem, ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0))
        goto err;

    BIO_free_all(b_cipher);

    /* --- Decryption Path --- */
    if (!TEST_ptr((b_mem_dec = BIO_new_mem_buf(ciphertext, ct_len))))
        goto err;
    if (!TEST_ptr((b_cipher_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_cipher_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    dec_len = BIO_read(b_cipher_dec, decrypted, sizeof(decrypted));
    if (!TEST_true(dec_len == pt_len))
        goto err;

    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dec_len))
        goto err;

    BIO_free_all(b_cipher_dec);
    return 1;

err:
    if (b_cipher) BIO_free_all(b_cipher);
    if (b_cipher_dec) BIO_free_all(b_cipher_dec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
