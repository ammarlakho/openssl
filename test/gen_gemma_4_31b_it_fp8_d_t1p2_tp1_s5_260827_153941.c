/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s5_260827_153941.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *benc = NULL, *bdec = NULL, *bmem = NULL, *bmem_out = NULL;
    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char iv[16] = "0123456789012345";
    const char *plaintext = "This is a test of the AES-256-CBC BIO round-trip encryption and decryption.";
    int pt_len = (int)strlen(plaintext);
    unsigned char *ciphertext = NULL;
    unsigned char *decrypted = NULL;
    int ct_len = 0;
    int rd_len = 0;

    /* 1. Encryption path: plaintext -> BIO_f_cipher -> BIO_s_mem */
    bmem_out = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem_out))
        goto err;

    benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(benc))
        goto err;

    if (!TEST_true(BIO_push(benc, bmem_out)))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(benc, plaintext, pt_len) > 0))
        goto err;

    /* Ensure final block/padding is processed */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL) > 0))
        goto err;

    /* Extract result for the round-trip */
    BIO_get_mem_ptr(bmem_out, &ciphertext, &ct_len);
    
    /* Use a local copy of ciphertext because BIO_free_all(benc) cleans up bmem_out */
    unsigned char *ct_copy = OPENSSL_malloc(ct_len);
    if (!TEST_ptr(ct_copy))
        goto err;
    memcpy(ct_copy, ciphertext, ct_len);

    BIO_free_all(benc);

    /* 2. Decryption path: BIO_s_mem(ciphertext) -> BIO_f_cipher -> BIO_s_mem(result) */
    bmem = BIO_new_mem_buf(ct_copy, ct_len);
    if (!TEST_ptr(bmem))
        goto err;

    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec))
        goto err;

    if (!TEST_true(BIO_push(bdec, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    decrypted = OPENSSL_malloc(pt_len + 16); /* space for potential padding */
    if (!TEST_ptr(decrypted))
        goto err;

    rd_len = BIO_read(bdec, (char *)decrypted, pt_len);
    if (rd_len <= 0)
        goto err;

    /* Validate outcome */
    if (!TEST_mem_eq(plaintext, pt_len, decrypted, rd_len))
        goto err;

    if (!TEST_true(rd_len == pt_len))
        goto err;

    ok = 1;

err:
    if (ct_copy)
        OPENSSL_free(ct_copy);
    if (decrypted)
        OPENSSL_free(decrypted);
    if (bdec)
        BIO_free_all(bdec);
    /* bmem is owned by bdec if pushed, otherwise it's separate */
    /* bmem_out is owned by benc if pushed */
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
