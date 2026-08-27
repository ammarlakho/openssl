/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p5_tp1_s10_260827_141749.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32], iv[16];
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen(plaintext);
    int cipher_len = 0;
    int dec_len = 0;
    int r;
    BIO *bmem_enc = NULL, *benc = NULL;
    BIO *bmem_dec = NULL, *bdec = NULL;

    /* Setup key and IV */
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    for (int i = 0; i < 16; i++) iv[i] = (unsigned char)i;

    /* --- Encryption Path --- */
    bmem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem_enc)) goto err;

    benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(benc)) goto err;

    if (!TEST_true(BIO_push(benc, bmem_enc))) goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(benc, plaintext, plain_len) > 0))
        goto err;

    /* Flush is mandatory to process padding and final block */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    cipher_len = BIO_read(bmem_enc, ciphertext, sizeof(ciphertext));
    if (cipher_len <= 0) goto err;

    BIO_free_all(benc);

    /* --- Decryption Path --- */
    bmem_dec = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem_dec)) goto err;

    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec)) goto err;

    if (!TEST_true(BIO_push(bdec, bmem_dec))) goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Write the ciphertext into the memory BIO so bdec can read it */
    if (!TEST_true(BIO_write(bmem_dec, ciphertext, cipher_len) > 0))
        goto err;

    /* Read from the cipher BIO until EOF to ensure all data is decrypted */
    while ((r = BIO_read(bdec, decrypted + dec_len, sizeof(decrypted) - dec_len)) > 0) {
        dec_len += r;
    }

    if (!TEST_mem_eq(plaintext, plain_len, decrypted, dec_len))
        goto err;

    BIO_free_all(bdec);
    return 1;

err:
    if (benc) BIO_free_all(benc);
    if (bdec) BIO_free_all(bdec);
    if (bmem_enc && !benc) BIO_free(bmem_enc);
    if (bmem_dec && !bdec) BIO_free(bmem_dec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
