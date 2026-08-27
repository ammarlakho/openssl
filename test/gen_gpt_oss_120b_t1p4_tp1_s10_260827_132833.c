/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s10_260827_132833.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        /* Round‑trip test for BIO_f_cipher (AES‑256‑CBC) */
        const unsigned char key[32] = { 0 };
        const unsigned char iv[16]  = { 0 };
        const char plain[] = "OpenSSL BIO f_cipher round‑trip test";
        const size_t plain_len = sizeof(plain) - 1;      /* without NUL */
        unsigned char *ciphertext = NULL;
        unsigned char outbuf[1024];
        int outlen = 0, i;
        BUF_MEM *bptr = NULL;

        /* ---------- encryption ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_enc))
            return 0;
        BIO *enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc)) {
            BIO_free(mem_enc);
            return 0;
        }
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                    key, iv, 1))) {
            BIO_free_all(enc);
            BIO_free(mem_enc);
            return 0;
        }
        enc = BIO_push(enc, mem_enc);

        if (!TEST_int_eq(BIO_write(enc, plain, (int)plain_len), (int)plain_len)) {
            BIO_free_all(enc);
            return 0;
        }
        if (!TEST_int_eq(BIO_flush(enc), 1)) {
            BIO_free_all(enc);
            return 0;
        }

        /* Extract ciphertext from the memory BIO */
        BIO_get_mem_ptr(mem_enc, &bptr);
        if (!TEST_ptr(bptr) || !TEST_int_gt(bptr->length, 0)) {
            BIO_free_all(enc);
            return 0;
        }
        ciphertext = OPENSSL_memdup(bptr->data, bptr->length);
        if (!TEST_ptr(ciphertext)) {
            BIO_free_all(enc);
            return 0;
        }
        /* Enc BIO owns the original memory BIO; free it now */
        BIO_free_all(enc);

        /* ---------- decryption ---------- */
        BIO *mem_dec = BIO_new_mem_buf(ciphertext, bptr->length);
        if (!TEST_ptr(mem_dec)) {
            OPENSSL_free(ciphertext);
            return 0;
        }
        BIO *dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec)) {
            BIO_free(mem_dec);
            OPENSSL_free(ciphertext);
            return 0;
        }
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                    key, iv, 0))) {
            BIO_free_all(dec);
            BIO_free(mem_dec);
            OPENSSL_free(ciphertext);
            return 0;
        }
        dec = BIO_push(dec, mem_dec);

        outlen = 0;
        while ((i = BIO_read(dec, outbuf + outlen,
                             (int)sizeof(outbuf) - outlen)) > 0) {
            outlen += i;
        }
        /* Ensure we read exactly the original plaintext */
        if (!TEST_int_eq(outlen, (int)plain_len)) {
            BIO_free_all(dec);
            OPENSSL_free(ciphertext);
            return 0;
        }
        if (!TEST_mem_eq(outbuf, outlen, plain, plain_len)) {
            BIO_free_all(dec);
            OPENSSL_free(ciphertext);
            return 0;
        }

        BIO_free_all(dec);
        OPENSSL_free(ciphertext);
        return 1;
    }
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
