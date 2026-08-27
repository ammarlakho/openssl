/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p6_tp1_s7_260827_130150.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test that BIO_f_cipher correctly encrypts and decrypts data using
         * AES‑256‑CBC.  The test builds an encryption chain (cipher BIO on top of a
         * memory BIO), writes some plaintext, flushes the chain and extracts the
         * ciphertext.  It then builds a decryption chain (cipher BIO on top of a
         * memory BIO that reads the ciphertext) and reads back the plaintext,
         * checking that it matches the original data. */
        const unsigned char key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        const unsigned char iv[16] = {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        };
        const char plaintext[] = "Test message for BIO cipher encryption/decryption.";
        const size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */

        /* ---------- Encryption ---------- */
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

        BIO_push(enc, mem_enc);

        if (!TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len)) {
            BIO_free_all(enc);
            return 0;
        }

        if (!TEST_int_gt(BIO_flush(enc), 0)) {
            BIO_free_all(enc);
            return 0;
        }

        /* Obtain ciphertext from the memory BIO */
        char *cipher_data = NULL;
        long cipher_len = BIO_get_mem_data(mem_enc, &cipher_data);
        if (!TEST_int_gt(cipher_len, 0)) {
            BIO_free_all(enc);
            return 0;
        }

        /* ---------- Decryption ---------- */
        BIO *mem_dec_src = BIO_new_mem_buf(cipher_data, (int)cipher_len);
        if (!TEST_ptr(mem_dec_src)) {
            BIO_free_all(enc);
            return 0;
        }

        BIO *dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec)) {
            BIO_free_all(enc);
            BIO_free(mem_dec_src);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                    key, iv, 0))) {
            BIO_free_all(enc);
            BIO_free_all(dec);
            BIO_free(mem_dec_src);
            return 0;
        }

        BIO_push(dec, mem_dec_src);

        unsigned char outbuf[1024];
        int outlen = BIO_read(dec, outbuf, sizeof(outbuf));
        if (!TEST_int_ge(outlen, 0)) {
            BIO_free_all(enc);
            BIO_free_all(dec);
            return 0;
        }

        int total = outlen;
        while ((outlen = BIO_read(dec, outbuf + total,
                                 (int)(sizeof(outbuf) - total))) > 0) {
            total += outlen;
            if (total >= (int)sizeof(outbuf))
                break; /* safety – test data is small */
        }

        /* Verify that the decrypted data matches the original plaintext */
        if (!TEST_mem_eq(outbuf, total, plaintext, pt_len)) {
            BIO_free_all(enc);
            BIO_free_all(dec);
            return 0;
        }

        /* Clean up */
        BIO_free_all(enc);   /* also frees mem_enc */
        BIO_free_all(dec);   /* also frees mem_dec_src */

        return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
