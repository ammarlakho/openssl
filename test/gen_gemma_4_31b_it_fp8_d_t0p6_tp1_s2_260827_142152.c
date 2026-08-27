/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p6_tp1_s2_260827_142152.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 0;
    BIO *b_mem = NULL, *b_cipher = NULL, *chain = NULL;
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    unsigned char ct_expected[48] = {
        0xf7, 0x1e, 0x54, 0x6c, 0x62, 0x2e, 0x1d, 0xb6, 0x22, 0x43, 0x8a, 0x4f, 0x00, 0x3d, 0xd2, 0x75,
        0x45, 0x70, 0x94, 0x5a, 0xf2, 0xd4, 0xb6, 0x9d, 0x81, 0x56, 0x7a, 0x4e, 0x4c, 0x8c, 0x2e, 0x82,
        0x9e, 0x92, 0x82, 0x26, 0x60, 0x8b, 0x39, 0x72, 0x19, 0xd9, 0x4d, 0x84, 0x4d, 0x07, 0xf3, 0x86
    };
    unsigned char ct_actual[64];
    unsigned char pt_actual[64];
    int actual_len;

    /* --- Test Encryption --- */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_cipher = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((chain = BIO_push(b_cipher, b_mem))))
        goto err;

    if (!TEST_true(BIO_set_cipher(chain, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(chain, plaintext, pt_len) == pt_len))
        goto err;

    /* Flush to process padding */
    if (!TEST_true(BIO_ctrl(chain, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    actual_len = BIO_read(b_mem, ct_actual, sizeof(ct_actual));
    if (!TEST_true(actual_len == 48))
        goto err;
    if (!TEST_mem_eq(ct_actual, 48, ct_expected, 48))
        goto err;

    BIO_free_all(chain);
    chain = b_cipher = b_mem = NULL;

    /* --- Test Decryption --- */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;
    
    /* Write the fixed ciphertext into the memory BIO */
    if (!TEST_true(BIO_write(b_mem, ct_expected, 48) == 48))
        goto err;

    if (!TEST_ptr((b_cipher = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((chain = BIO_push(b_cipher, b_mem))))
        goto err;

    if (!TEST_true(BIO_set_cipher(chain, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted plaintext */
    actual_len = BIO_read(chain, pt_actual, sizeof(pt_actual) - 1);
    if (actual_len <= 0)
        goto err;
    pt_actual[actual_len] = '\0';

    if (!TEST_mem_eq(pt_actual, pt_len, plaintext, pt_len))
        goto err;
    if (!TEST_true(actual_len == pt_len))
        goto err;

    ok = 1;

err:
    if (chain)
        BIO_free_all(chain);
    else {
        if (b_cipher) BIO_free(b_cipher);
        if (b_mem) BIO_free(b_mem);
    }
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
