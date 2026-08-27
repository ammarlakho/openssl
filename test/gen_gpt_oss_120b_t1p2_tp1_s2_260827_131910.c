/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s2_260827_131910.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    /* Simple deterministic round‑trip test for AES‑256‑CBC using the
     * BIO_f_cipher filter.  The test encrypts a known plaintext with a
     * zero key / zero IV, obtains the ciphertext from a memory BIO, then
     * decrypts that ciphertext and checks that the original plaintext is
     * recovered and that the cipher reports success. */
    const unsigned char key[32] = {0};          /* 256‑bit zero key   */
    const unsigned char iv[16]  = {0};          /* 128‑bit zero IV    */
    const unsigned char plaintext[] =
        "OpenSSL BIO AES‑256‑CBC round‑trip test vector.";
    const size_t pt_len = sizeof(plaintext) - 1;/* omit trailing NUL */
    unsigned char outbuf[256];
    size_t outlen = 0;
    BIO *mem = NULL, *enc = NULL, *dec = NULL, *src = NULL;
    BUF_MEM *bptr = NULL;
    int ret;

    /* ---------- encrypt ---------- */
    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem))
        goto err;
    enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc))
        goto err;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* 1 = encrypt */
        goto err;
    BIO_push(enc, mem);

    ret = BIO_write(enc, plaintext, (int)pt_len);
    if (!TEST_int_eq(ret, (int)pt_len))
        goto err;

    /* Flush forces final block processing */
    if (!TEST_true(BIO_flush(enc)))
        goto err;

    /* Grab the ciphertext from the memory BIO */
    BIO_get_mem_ptr(mem, &bptr);
    if (!TEST_ptr(bptr))
        goto err;
    /* bptr->data is not NUL terminated, use length */
    const unsigned char *ciphertext = (const unsigned char *)bptr->data;
    const size_t ct_len = bptr->length;

    /* ---------- decrypt ---------- */
    src = BIO_new_mem_buf(ciphertext, (int)ct_len);
    if (!TEST_ptr(src))
        goto err;
    dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec))
        goto err;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* 0 = decrypt */
        goto err;
    BIO_push(dec, src);

    /* Read back the plaintext */
    outlen = 0;
    while (outlen < pt_len) {
        ret = BIO_read(dec, outbuf + outlen,
                       (int)(sizeof(outbuf) - outlen));
        if (ret <= 0) {
            if (BIO_should_retry(dec))
                continue;
            break;
        }
        outlen += (size_t)ret;
    }

    if (!TEST_size_t_eq(outlen, pt_len))
        goto err;
    if (!TEST_mem_eq(outbuf, pt_len, plaintext, pt_len))
        goto err;

    /* Verify that the cipher reports a successful operation */
    if (!TEST_true(BIO_ctrl(dec, BIO_C_GET_CIPHER_STATUS, 0, NULL)))
        goto err;

    /* success */
    BIO_free_all(enc);
    BIO_free_all(dec);
    return 1;

err:
    BIO_free_all(enc);
    BIO_free_all(dec);
    BIO_free_all(mem);
    BIO_free_all(src);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
