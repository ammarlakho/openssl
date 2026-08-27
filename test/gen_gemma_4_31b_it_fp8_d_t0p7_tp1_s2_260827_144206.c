/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s2_260827_144206.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const char *plaintext = "The quick brown fox jumps over the lazy dog. "
                            "This is a test of the BIO_f_cipher implementation "
                            "to ensure that AES-256-CBC round-trip works correctly "
                            "across block boundaries and with padding.";
    int plain_len = (int)strlen(plaintext);
    unsigned char decrypted[1024];
    int dec_len = 0;
    int ret = 0;

    BIO *b_mem_out = NULL, *b_enc = NULL;
    BIO *b_mem_in = NULL, *b_dec = NULL;

    /* 1. Setup Encryption Chain: b_enc (Cipher) -> b_mem_out (Mem) */
    if (!TEST_ptr((b_mem_out = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_enc = BIO_push(b_mem_out, BIO_f_cipher()))))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, plaintext, plain_len) == plain_len))
        goto err;

    /* Flush to ensure padding is processed and written to the underlying BIO */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* 2. Extract Ciphertext from b_mem_out */
    unsigned char *ct_ptr = NULL;
    long ct_len = BIO_get_mem_data(b_mem_out, &ct_ptr);
    if (!TEST_true(ct_len > 0))
        goto err;

    /* 3. Setup Decryption Chain: b_dec (Cipher) -> b_mem_in (Mem) */
    if (!TEST_ptr((b_mem_in = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_true(BIO_write(b_mem_in, ct_ptr, ct_len) == ct_len))
        goto err;

    if (!TEST_ptr((b_dec = BIO_push(b_mem_in, BIO_f_cipher()))))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    while ((ret = BIO_read(b_dec, (char *)decrypted + dec_len, 
                           (int)sizeof(decrypted) - dec_len)) > 0) {
        dec_len += ret;
    }

    if (ret < 0)
        goto err;

    /* 4. Final Verification */
    if (!TEST_true(dec_len == plain_len))
        goto err;

    if (!TEST_mem_eq((unsigned char *)plaintext, plain_len, decrypted, dec_len))
        goto err;

    BIO_free(b_enc);
    BIO_free(b_dec);
    return 1;

err:
    if (b_enc) BIO_free(b_enc);
    if (b_dec) BIO_free(b_dec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
