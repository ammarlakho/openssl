/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p6_tp1_s4_260827_130026.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
{
    /* Test AES‑256‑CBC encryption/decryption using the BIO_f_cipher filter. */
    static const unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const unsigned char iv[16] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
        0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
    };
    const char plaintext[] = "The quick brown fox jumps over the lazy dog";
    const int plain_len = (int)strlen(plaintext);
    unsigned char *ciphertext = NULL;
    long cipher_len = 0;
    BIO *mem = NULL, *enc = NULL, *dec = NULL, *cipher_in = NULL;
    int ret;

    /* ---------- Encryption side ---------- */
    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem))
        return 0;

    enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc))
        return 0;

    BIO_push(enc, mem);

    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))      /* encrypt */
        return 0;

    ret = BIO_write(enc, plaintext, plain_len);
    if (!TEST_int_eq(ret, plain_len))
        return 0;

    if (!TEST_true(BIO_flush(enc)))
        return 0;

    /* Retrieve the ciphertext from the memory BIO */
    cipher_len = BIO_get_mem_data(mem, &ciphertext);
    if (!TEST_true(cipher_len > 0))
        return 0;
    if (!TEST_ptr(ciphertext))
        return 0;

    /* ---------- Decryption side ---------- */
    cipher_in = BIO_new_mem_buf(ciphertext, (int)cipher_len);
    if (!TEST_ptr(cipher_in))
        return 0;

    dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec))
        return 0;

    BIO_push(dec, cipher_in);

    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))      /* decrypt */
        return 0;

    {
        unsigned char outbuf[256];
        int outlen;

        outlen = BIO_read(dec, outbuf, sizeof(outbuf));
        if (!TEST_int_eq(outlen, plain_len))
            return 0;
        if (!TEST_mem_eq(outbuf, outlen, plaintext, plain_len))
            return 0;
    }

    /* Clean up */
    BIO_free_all(enc);   /* frees enc and the underlying mem BIO */
    BIO_free_all(dec);   /* frees dec and cipher_in */

    return 1;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
