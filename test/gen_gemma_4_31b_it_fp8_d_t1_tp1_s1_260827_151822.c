/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s1_260827_151822.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    const char *plaintext = "This is a test of the OpenSSL BIO cipher filter round-trip!";
    int pt_len = (int)strlen(plaintext);
    
    BIO *b_mem_enc = NULL, *b_enc = NULL;
    BIO *b_mem_dec = NULL, *b_dec = NULL;
    unsigned char *ciphertext = NULL;
    long ct_len = 0;
    unsigned char decrypted[256];
    int dec_len = 0;
    int ret = 0;

    /* Encryption phase */
    if (!TEST_ptr((b_mem_enc = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_enc, b_mem_enc)))
        goto err;
    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, plaintext, pt_len) > 0))
        goto err;
    if (!TEST_true(BIO_flush(b_enc)))
        goto err;

    /* Extract ciphertext from the memory BIO */
    ct_len = BIO_get_mem_data(b_mem_enc, &ciphertext);
    if (ct_len <= 0 || ciphertext == NULL)
        goto err;

    BIO_free_all(b_enc);
    b_enc = NULL;

    /* Decryption phase */
    if (!TEST_ptr((b_mem_dec = BIO_new_mem_buf(ciphertext, ct_len))))
        goto err;
    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;
    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    int r;
    while ((r = BIO_read(b_dec, (char *)decrypted + dec_len, sizeof(decrypted) - dec_len)) > 0) {
        dec_len += r;
    }

    if (r < 0)
        goto err;

    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dec_len))
        goto err;

    ret = 1;

err:
    BIO_free_all(b_enc);
    BIO_free_all(b_dec);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
