/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s10_260827_131333.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
static int test_bio_enc_generated(void)
{
    /* Test vectors (AES‑256‑CBC) */
    static const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const unsigned char plaintext[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    static const unsigned char expected_ct[16] = {
        0xf3,0xee,0xd1,0xbd,0xb5,0xd2,0xa0,0x3c,
        0x06,0x4b,0x5a,0x7e,0x3d,0xb1,0x81,0xf8
    };

    /* ---------- Encryption ---------- */
    BIO *mem_enc = BIO_new(BIO_s_mem());
    BIO *enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(mem_enc) || !TEST_ptr(enc))
        return 0;

    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1))) {
        BIO_free_all(enc);
        return 0;
    }

    /* chain: enc -> mem_enc */
    BIO_push(enc, mem_enc);

    if (!TEST_int_gt(BIO_write(enc, plaintext, sizeof(plaintext)),
                     0))
        goto end_fail;

    if (!TEST_int_eq(BIO_flush(enc), 1))
        goto end_fail;

    /* Retrieve ciphertext from the memory BIO */
    BUF_MEM *bptr = NULL;
    if (!TEST_true(BIO_get_mem_ptr(mem_enc, &bptr)))
        goto end_fail;
    if (!TEST_int_eq(bptr->length, (int)sizeof(expected_ct)))
        goto end_fail;
    if (!TEST_mem_eq(bptr->data, bptr->length,
                     expected_ct, sizeof(expected_ct)))
        goto end_fail;

    /* Verify cipher status flag is OK */
    if (!TEST_int_eq(BIO_ctrl(enc, BIO_C_GET_CIPHER_STATUS, 0, NULL), 1))
        goto end_fail;

    BIO_free_all(enc);   /* also frees mem_enc */

    /* ---------- Decryption ---------- */
    BIO *mem_dec = BIO_new_mem_buf(expected_ct, sizeof(expected_ct));
    BIO *dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(mem_dec) || !TEST_ptr(dec))
        return 0;

    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0))) {
        BIO_free_all(dec);
        return 0;
    }

    /* chain: dec -> mem_dec */
    BIO_push(dec, mem_dec);

    unsigned char outbuf[32];
    int outlen = BIO_read(dec, outbuf, sizeof(outbuf));
    if (!TEST_int_eq(outlen, (int)sizeof(plaintext)))
        goto end_fail;
    if (!TEST_mem_eq(outbuf, outlen, plaintext, sizeof(plaintext)))
        goto end_fail;

    /* Clean up */
    BIO_free_all(dec);
    return 1;

end_fail:
    BIO_free_all(enc);
    BIO_free_all(dec);
    return 0;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
