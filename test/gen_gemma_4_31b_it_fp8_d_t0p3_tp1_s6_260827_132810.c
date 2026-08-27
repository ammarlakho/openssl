/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p3_tp1_s6_260827_132810.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *bmem = NULL, *bcipher = NULL, *bmem_dec = NULL, *bcipher_dec = NULL;
    unsigned char key[32], iv[16];
    unsigned char ciphertext[512], recovered[512];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    int ct_len, rec_len;

    /* Initialize key and IV with fixed values */
    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* 1. Encryption Phase */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((bcipher = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(bcipher, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(bcipher, plaintext, pt_len) == pt_len))
        goto err;

    /* Flush is required to process the final block and padding */
    if (!TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Read the resulting ciphertext from the memory BIO */
    ct_len = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (ct_len <= 0)
        goto err;

    BIO_free_all(bcipher);

    /* 2. Decryption Phase */
    if (!TEST_ptr((bmem_dec = BIO_new_mem_buf(ciphertext, ct_len))))
        goto err;
    if (!TEST_ptr((bcipher_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(bcipher_dec, bmem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bcipher_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read from the cipher BIO to decrypt the data */
    rec_len = BIO_read(bcipher_dec, recovered, sizeof(recovered));
    if (rec_len <= 0)
        goto err;

    /* Final check: recovered plaintext must match original */
    if (!TEST_true(rec_len == pt_len))
        goto err;
    if (!TEST_mem_eq(plaintext, pt_len, recovered, rec_len))
        goto err;

    BIO_free_all(bcipher_dec);
    return 1;

err:
    if (bcipher)
        BIO_free_all(bcipher);
    if (bcipher_dec)
        BIO_free_all(bcipher_dec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
