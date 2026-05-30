/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: generated_test.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "testutil.h"

static int test_bio_enc_generated_smoke(void)
{
    /* BEGIN_LLM_REPLACE */
{
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
    };
    const unsigned char plaintext[] =
        "OpenSSL BIO cipher AES-256-CBC round‑trip test vector";
    const size_t pt_len = sizeof(plaintext) - 1; /* exclude trailing NUL */

    /* ---------- Encryption ---------- */
    BIO *mem_enc = BIO_new(BIO_s_mem());
    BIO *cipher_enc = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_enc) || !TEST_ptr(cipher_enc))
        goto err;

    if (!TEST_true(BIO_set_cipher(cipher_enc,
                                 EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* 1 = encrypt */
        goto err;

    /* Chain: cipher_enc -> mem_enc */
    BIO_push(cipher_enc, mem_enc);

    if (!TEST_int_eq(BIO_write(cipher_enc, plaintext, (int)pt_len), (int)pt_len))
        goto err;

    if (!TEST_int_ge(BIO_flush(cipher_enc), 0))
        goto err;

    /* Retrieve ciphertext from the memory BIO */
    unsigned char *cdata = NULL;
    long c_len = BIO_get_mem_data(mem_enc, &cdata);
    if (!TEST_long_gt(c_len, 0))
        goto err;

    /* ---------- Decryption ---------- */
    BIO *mem_dec = BIO_new_mem_buf(cdata, c_len);
    BIO *cipher_dec = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_dec) || !TEST_ptr(cipher_dec))
        goto err;

    if (!TEST_true(BIO_set_cipher(cipher_dec,
                                 EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* 0 = decrypt */
        goto err;

    /* Chain: cipher_dec -> mem_dec */
    BIO_push(cipher_dec, mem_dec);

    unsigned char decrypted[512];
    int total = 0;

    for (;;) {
        int r = BIO_read(cipher_dec,
                         decrypted + total,
                         (int)sizeof(decrypted) - total);
        if (r > 0) {
            total += r;
            continue;
        }
        if (BIO_should_retry(cipher_dec))
            continue;
        break;
    }

    if (!TEST_int_eq(total, (int)pt_len))
        goto err;

    if (!TEST_mem_eq(decrypted, pt_len, plaintext, pt_len))
        goto err;

    /* Cleanup */
    BIO_free_all(cipher_enc);   /* also frees mem_enc */
    BIO_free_all(cipher_dec);   /* also frees mem_dec */
    return 1;

err:
    if (cipher_enc != NULL)
        BIO_free_all(cipher_enc);
    else if (mem_enc != NULL)
        BIO_free(mem_enc);
    if (cipher_dec != NULL)
        BIO_free_all(cipher_dec);
    else if (mem_dec != NULL)
        BIO_free(mem_dec);
    return 0;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated_smoke);
    return 1;
}
 
