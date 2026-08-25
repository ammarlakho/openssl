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
        int ret = 0;
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const char *plain = "The quick brown fox jumps over the lazy dog";
        size_t plain_len = strlen(plain);
        unsigned char outbuf[256];
        int outlen = 0, i, n;
        BIO *mem = NULL, *enc = NULL;
        BIO *mem2 = NULL, *dec = NULL;
        char *cipher_data = NULL;
        long cipher_len = 0;
        EVP_CIPHER_CTX *cctx = NULL;

        /* ---------- encryption ---------- */
        mem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem))
            goto out;
        enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc))
            goto out;
        BIO_push(enc, mem);

        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* 1 = encrypt */
            goto out;

        n = BIO_write(enc, plain, (int)plain_len);
        if (!TEST_int_eq(n, (int)plain_len))
            goto out;

        if (!TEST_true(BIO_flush(enc)))
            goto out;

        /* fetch ciphertext from the underlying memory BIO */
        cipher_len = BIO_get_mem_data(mem, &cipher_data);
        if (!TEST_int_gt(cipher_len, 0))
            goto out;

        /* ---------- decryption ---------- */
        /* create a read‑only memory BIO that contains the ciphertext */
        mem2 = BIO_new_mem_buf(cipher_data, (int)cipher_len);
        if (!TEST_ptr(mem2))
            goto out;
        dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec))
            goto out;
        BIO_push(dec, mem2);

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* 0 = decrypt */
            goto out;

        /* read back the decrypted data */
        outlen = 0;
        while ((i = BIO_read(dec, outbuf + outlen,
                             (int)sizeof(outbuf) - outlen)) > 0) {
            outlen += i;
            if (outlen >= (int)sizeof(outbuf))
                break;
        }
        if (!TEST_int_gt(outlen, 0))
            goto out;

        /* compare plaintext with decrypted output (ignore possible padding) */
        if (!TEST_mem_eq(plain, plain_len, outbuf, plain_len))
            goto out;

        /* verify that the cipher context reports success */
        if (!TEST_true(BIO_ctrl(dec, BIO_C_GET_CIPHER_STATUS, 0, NULL)))
            goto out;

        /* optional: ensure we can retrieve the EVP_CIPHER_CTX via control */
        if (!TEST_true(BIO_ctrl(dec, BIO_C_GET_CIPHER_CTX,
                               0, &cctx)) || !TEST_ptr(cctx))
            goto out;

        ret = 1;        /* all checks passed */

out:
        BIO_free_all(enc);
        BIO_free_all(dec);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated_smoke);
    return 1;
}
