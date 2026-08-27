/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p8_tp1_s10_260827_151657.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pl_len = (int)strlen(plaintext);
    unsigned char ciphertext[256];
    unsigned char decrypted[256];
    int ct_len = 0;
    int dec_len = 0;
    BIO *benc = NULL, *bdec = NULL, *bmem = NULL;

    /* 1. Encryption Phase */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        return 0;

    benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(benc))
        goto err;

    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(benc, plaintext, pl_len) > 0))
        goto err;

    /* Flush to process final block/padding */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Read ciphertext from the memory BIO */
    ct_len = BIO_read(bmem, (char *)ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0))
        goto err;

    /* Ensure it's actually encrypted (not plaintext) */
    if (TEST_mem_eq(plaintext, pl_len, ciphertext, pl_len))
        goto err;

    /* 2. Decryption Phase */
    /* Create a new chain: cipher BIO -> mem BIO containing ciphertext */
    BIO *bmem_in = BIO_new_mem_buf(ciphertext, ct_len);
    if (!TEST_ptr(bmem_in))
        goto err;

    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec)) {
        BIO_free(bmem_in);
        goto err;
    }

    if (!TEST_true(BIO_push(bdec, bmem_in)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    dec_len = BIO_read(bdec, (char *)decrypted, sizeof(decrypted));
    if (dec_len < 0)
        goto err;

    /* Flush to get the final padding block */
    if (!TEST_true(BIO_ctrl(bdec, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    int final_bytes = BIO_read(bdec, (char *)decrypted + dec_len, sizeof(decrypted) - dec_len);
    if (final_bytes < 0)
        goto err;
    dec_len += final_bytes;

    /* Verify round-trip result */
    if (!TEST_mem_eq(plaintext, pl_len, decrypted, dec_len))
        goto err;

    BIO_free_all(benc);
    BIO_free_all(bdec);
    return 1;

err:
    if (benc) BIO_free_all(benc);
    if (bdec) BIO_free_all(bdec);
    if (bmem) BIO_free(bmem);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
