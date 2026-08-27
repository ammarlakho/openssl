/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p8_tp1_s6_260827_150824.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *benc = NULL, *bdec = NULL, *bmem = NULL;
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plaintext_len = (int)strlen(plaintext);
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int enc_len = 0, dec_len = 0;

    /* 1. Encryption Path: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((benc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(benc, plaintext, plaintext_len) > 0))
        goto err;

    /* Flush to ensure EVP_CipherFinal_ex is called and padding is written */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from memory BIO to verify it's not plaintext */
    enc_len = BIO_read(bmem, (char *)ciphertext, sizeof(ciphertext));
    if (enc_len <= 0)
        goto err;
    if (TEST_mem_eq(plaintext, plaintext_len, ciphertext, enc_len))
        goto err; /* Should not be equal */

    /* 2. Decryption Path: BIO_f_cipher -> BIO_s_mem (reset) */
    /* Reset memory BIO offset to the beginning for reading ciphertext */
    if (!TEST_true(BIO_set_mem_offset(bmem, 0)))
        goto err;

    /* We can reuse bmem, but we need a new cipher filter for decryption */
    if (!TEST_ptr((bdec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(bdec, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    dec_len = BIO_read(bdec, (char *)decrypted, sizeof(decrypted));
    if (dec_len <= 0)
        goto err;

    /* Verify round-trip result */
    if (!TEST_true(dec_len == plaintext_len))
        goto err;
    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, dec_len))
        goto err;

    BIO_free_all(benc);
    BIO_free_all(bdec);
    return 1;

err:
    BIO_free_all(benc);
    BIO_free_all(bdec);
    /* bmem is usually part of the chain, but if push failed, it might need separate free */
    if (bmem && benc == NULL && bdec == NULL)
        BIO_free(bmem);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
