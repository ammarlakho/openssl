/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp1_s2_260827_123855.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    const char *plaintext = "OpenSSL BIO cipher round‑trip test data";
    size_t pt_len = strlen(plaintext);
    BIO *mem = NULL, *cipher = NULL;
    BIO *mem2 = NULL, *dec = NULL;
    long c_len = 0;
    const char *c_buf = NULL;
    unsigned char outbuf[256];
    int outlen = 0;
    int ok = 0;               /* return value */

    /* ---------- encryption ---------- */
    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem))
        goto end;
    cipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(cipher))
        goto end;
    if (!TEST_true(BIO_set_cipher(cipher, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* encrypt */
        goto end;
    BIO_push(cipher, mem);
    if (!TEST_int_eq(BIO_write(cipher, plaintext, (int)pt_len), (int)pt_len))
        goto end;
    if (!TEST_true(BIO_flush(cipher)))
        goto end;

    /* obtain ciphertext from the memory BIO */
    c_len = BIO_get_mem_data(mem, &c_buf);
    if (!TEST_int_gt(c_len, 0))
        goto end;

    /* ---------- decryption ---------- */
    mem2 = BIO_new_mem_buf(c_buf, (int)c_len);
    if (!TEST_ptr(mem2))
        goto end;
    dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec))
        goto end;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* decrypt */
        goto end;
    BIO_push(dec, mem2);
    outlen = BIO_read(dec, outbuf, sizeof(outbuf));
    if (!TEST_int_gt(outlen, 0))
        goto end;

    /* compare decrypted data with original plaintext */
    if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len))
        goto end;

    ok = 1;   /* all checks passed */

end:
    BIO_free_all(cipher);   /* frees mem as well */
    BIO_free_all(dec);      /* frees mem2 as well */
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
