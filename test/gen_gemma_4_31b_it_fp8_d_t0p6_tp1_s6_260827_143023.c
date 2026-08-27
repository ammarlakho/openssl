/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p6_tp1_s6_260827_143023.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_enc = NULL, *b_mem_enc = NULL;
    BIO *b_dec = NULL, *b_mem_dec = NULL;
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    unsigned char result[1024];
    unsigned char *ct_ptr = NULL;
    long ct_len = 0;
    int read_len = 0;
    int i;

    /* 1. Encryption: Plaintext -> BIO_f_cipher (Enc) -> BIO_s_mem */
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

    /* Flush is required to process the final block and padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from memory BIO */
    BIO_get_mem_data(b_mem_enc, &ct_ptr, &ct_len);
    if (!TEST_true(ct_ptr != NULL && ct_len > 0))
        goto err;

    /* 2. Decryption: BIO_s_mem (Ciphertext) -> BIO_f_cipher (Dec) -> Plaintext */
    if (!TEST_ptr((b_mem_dec = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_true(BIO_write(b_mem_dec, ct_ptr, (int)ct_len) > 0))
        goto err;

    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data until EOF */
    while ((i = BIO_read(b_dec, result + read_len, (int)sizeof(result) - read_len)) > 0) {
        read_len += i;
    }

    if (!TEST_true(read_len == pt_len))
        goto err;

    if (!TEST_mem_eq(plaintext, pt_len, result, read_len))
        goto err;

    ok = 1;

err:
    BIO_free_all(b_enc);
    BIO_free_all(b_dec);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
