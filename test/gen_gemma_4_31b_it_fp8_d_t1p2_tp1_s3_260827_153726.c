/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s3_260827_153726.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ret = 0;
    BIO *b_mem = NULL, *b_cipher = NULL;
    BIO *b_mem_dec = NULL, *b_cipher_dec = NULL;
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                               0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                               0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog across the BIO!";
    int pt_len = (int)sizeof(plaintext) - 1;
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0, dec_len = 0;

    /* 1. Encryption: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;

    if (!TEST_ptr((b_cipher = BIO_push(b_mem, BIO_f_cipher()))))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_cipher, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_cipher, (const char *)plaintext, pt_len) > 0))
        goto err;

    /* Ensure padding and final block are written to memory BIO */
    if (!TEST_true(BIO_ctrl(b_cipher, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from the memory BIO */
    ct_len = BIO_read(b_mem, (char *)ciphertext, (int)sizeof(ciphertext));
    if (ct_len <= 0)
        goto err;

    BIO_free_all(b_cipher);
    b_cipher = NULL;

    /* 2. Decryption: BIO_f_cipher -> BIO_s_mem (containing ciphertext) */
    if (!TEST_ptr((b_mem_dec = BIO_new_mem_buf(ciphertext, ct_len))))
        goto err;

    if (!TEST_ptr((b_cipher_dec = BIO_push(b_mem_dec, BIO_f_cipher()))))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_cipher_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read the decrypted plaintext */
    dec_len = BIO_read(b_cipher_dec, (char *)decrypted, (int)sizeof(decrypted));
    if (dec_len <= 0)
        goto err;

    if (!TEST_mem_eq(decrypted, dec_len, plaintext, pt_len))
        goto err;

    ret = 1;

err:
    BIO_free_all(b_cipher);
    BIO_free_all(b_cipher_dec);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
