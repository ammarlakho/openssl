/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p4_tp1_s4_260827_125211.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test BIO_f_cipher round‑trip with AES‑256‑CBC.
         * 1. Encrypt a known plaintext using a BIO chain (cipher → mem).
         * 2. Decrypt the resulting ciphertext using a second BIO chain
         *    (cipher → mem‑buf) and verify the output matches the original.
         */
        const unsigned char key[32] = {0};          /* 256‑bit all‑zero key */
        const unsigned char iv[16]  = {0};          /* 128‑bit all‑zero IV */
        const char plaintext[] = "OpenSSL BIO cipher round‑trip test";
        const size_t pt_len = strlen(plaintext);
        BIO *mem = NULL, *enc = NULL;
        BUF_MEM *bptr = NULL;
        unsigned char *ciphertext = NULL;
        size_t ct_len = 0;
        BIO *mem_in = NULL, *dec = NULL;
        unsigned char outbuf[128];
        int outlen = 0;

        /* ---------- Encryption side ---------- */
        mem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem))
            return 0;

        enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc)) {
            BIO_free(mem);
            return 0;
        }
        BIO_push(enc, mem);

        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                      key, iv, 1))) {
            BIO_free_all(enc);
            return 0;
        }

        if (!TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len)) {
            BIO_free_all(enc);
            return 0;
        }

        if (!TEST_true(BIO_flush(enc))) {
            BIO_free_all(enc);
            return 0;
        }

        /* Retrieve ciphertext from the memory BIO */
        if (!TEST_true(BIO_get_mem_ptr(mem, &bptr))) {
            BIO_free_all(enc);
            return 0;
        }
        ciphertext = (unsigned char *)bptr->data;
        ct_len = bptr->length;
        if (!TEST_int_gt((int)ct_len, 0))
            return 0;

        /* ---------- Decryption side ---------- */
        mem_in = BIO_new_mem_buf(ciphertext, (int)ct_len);
        if (!TEST_ptr(mem_in)) {
            BIO_free_all(enc);
            return 0;
        }

        dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec)) {
            BIO_free_all(enc);
            BIO_free(mem_in);
            return 0;
        }
        BIO_push(dec, mem_in);

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0))) {
            BIO_free_all(enc);
            BIO_free_all(dec);
            return 0;
        }

        outlen = BIO_read(dec, outbuf, sizeof(outbuf));
        if (!TEST_int_eq(outlen, (int)pt_len))
            return 0;

        if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len))
            return 0;

        /* Clean up */
        BIO_free_all(enc);
        BIO_free_all(dec);
        return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
