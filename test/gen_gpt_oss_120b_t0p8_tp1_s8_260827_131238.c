/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s8_260827_131238.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test AES‑256‑CBC encryption and decryption using BIO_f_cipher */
    const unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    const unsigned char iv[16] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
        0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
    };
    const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog";
    const size_t pt_len = sizeof(plaintext) - 1; /* omit terminating NUL */

    BIO *mem_enc = NULL, *enc = NULL;
    BIO *mem_dec = NULL, *dec = NULL;
    char *enc_data = NULL;
    long enc_len = 0;
    unsigned char outbuf[256];
    int outlen = 0;
    int ok = 0; /* default failure */

    /* ---------- encryption ---------- */
    mem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem_enc))
        goto end;

    enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc))
        goto end;

    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))      /* 1 = encrypt */
        goto end;

    /* push encryption filter on top of the memory BIO */
    enc = BIO_push(enc, mem_enc);

    if (!TEST_int_gt(BIO_write(enc, plaintext, (int)pt_len), 0))
        goto end;
    if (!TEST_int_eq(BIO_flush(enc), 1))
        goto end;

    /* obtain ciphertext from the memory BIO */
    enc_len = BIO_get_mem_data(mem_enc, &enc_data);
    if (!TEST_long_gt(enc_len, 0))
        goto end;

    /* ---------- decryption ---------- */
    mem_dec = BIO_new_mem_buf(enc_data, (int)enc_len);
    if (!TEST_ptr(mem_dec))
        goto end;

    dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec))
        goto end;

    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))      /* 0 = decrypt */
        goto end;

    /* push decryption filter on top of the memory BIO containing cipher */
    dec = BIO_push(dec, mem_dec);

    outlen = BIO_read(dec, outbuf, sizeof(outbuf));
    if (!TEST_int_gt(outlen, 0))
        goto end;

    /* sanity: decrypted length must match original length */
    if (!TEST_int_eq(outlen, (int)pt_len))
        goto end;

    /* compare decrypted data with original plaintext */
    if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len))
        goto end;

    /* all checks passed */
    ok = 1;

end:
    BIO_free_all(enc);
    BIO_free_all(dec);
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
