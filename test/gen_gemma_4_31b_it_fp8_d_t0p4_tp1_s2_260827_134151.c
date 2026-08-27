/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s2_260827_134151.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *bmem = NULL, *benc = NULL, *bdec = NULL;
    unsigned char key[32], iv[16], out[1024];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int len = (int)strlen(plaintext);
    int read_len = 0, n;

    /* Initialize key and IV with fixed values for determinism */
    memset(key, 0x42, 32);
    memset(iv, 0x24, 16);
    memset(out, 0, sizeof(out));

    /* 1. Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;

    /* Configure AES-256-CBC for encryption */
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext and flush to ensure padding is processed */
    if (!TEST_true(BIO_write(benc, plaintext, len) == len))
        goto err;
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Detach encryption filter and reset memory BIO for reading */
    BIO_free(benc);
    benc = NULL;
    BIO_reset(bmem);

    /* 2. Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_push(bdec, bmem)))
        goto err;

    /* Configure AES-256-CBC for decryption */
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data until EOF */
    while (read_len < (int)sizeof(out)) {
        n = BIO_read(bdec, out + read_len, (int)sizeof(out) - read_len);
        if (n <= 0)
            break;
        read_len += n;
    }

    /* Verify the round-trip result matches original plaintext */
    if (!TEST_mem_eq(out, read_len, plaintext, len))
        goto err;

    ok = 1;

err:
    if (benc)
        BIO_free(benc);
    if (bdec)
        BIO_free_all(bdec);
    else if (bmem)
        BIO_free(bmem);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
