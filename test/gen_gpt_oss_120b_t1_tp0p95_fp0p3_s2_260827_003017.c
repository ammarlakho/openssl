/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp0p95_fp0p3_s2_260827_003017.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vector: encrypt then decrypt using BIO_f_cipher (AES‑256‑CBC) */
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32];
    unsigned char iv[16];
    const char *plain = "OpenSSL BIO cipher test vector";
    int plain_len = (int)strlen(plain);
    unsigned char outbuf[128];
    long status;
    char *cdata = NULL;
    long cdata_len;
    BIO *mem = NULL, *enc = NULL, *mem2 = NULL, *dec = NULL;
    int ret;

    /* initialise deterministic key/iv */
    for (int i = 0; i < 32; i++)
        key[i] = (unsigned char)i;
    for (int i = 0; i < 16; i++)
        iv[i] = (unsigned char)(i + 0x10);

    /* ---------- encryption ---------- */
    mem = BIO_new(BIO_s_mem());
    TEST_ptr(mem);
    enc = BIO_new(BIO_f_cipher());
    TEST_ptr(enc);
    TEST_true(BIO_set_cipher(enc, cipher, key, iv, 1));   /* encrypt */
    BIO_push(enc, mem);

    /* write plaintext */
    ret = BIO_write(enc, plain, plain_len);
    TEST_int_eq(ret, plain_len);
    TEST_true(BIO_flush(enc));

    /* obtain ciphertext from the memory BIO */
    cdata_len = BIO_get_mem_data(mem, &cdata);
    TEST_int_gt(cdata_len, plain_len);   /* padding makes it longer */

    /* ---------- decryption ---------- */
    mem2 = BIO_new_mem_buf(cdata, (int)cdata_len);
    TEST_ptr(mem2);
    dec = BIO_new(BIO_f_cipher());
    TEST_ptr(dec);
    TEST_true(BIO_set_cipher(dec, cipher, key, iv, 0));   /* decrypt */
    BIO_push(dec, mem2);

    /* read decrypted data */
    ret = BIO_read(dec, outbuf, sizeof(outbuf));
    TEST_int_gt(ret, 0);
    TEST_mem_eq(outbuf, ret, plain, plain_len);

    /* check that the cipher reported success */
    status = BIO_ctrl(dec, BIO_C_GET_CIPHER_STATUS, 0, NULL);
    TEST_int_eq(status, 1);

    /* clean up */
    BIO_free_all(enc);
    BIO_free_all(dec);
    return 1;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
