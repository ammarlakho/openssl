/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s4_260827_131039.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        int ok = 1;
        const unsigned char key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        const unsigned char iv[16] = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
        };
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog 1234567890";
        const size_t plen = sizeof(plaintext) - 1; /* without trailing NUL */

        /* ------------------------------------------------------------
         * 1. Compute the expected ciphertext using the EVP API.
         * ------------------------------------------------------------ */
        EVP_CIPHER_CTX *evp_ctx = NULL;
        unsigned char *expected_ct = NULL;
        int evp_len = 0, evp_tmp = 0, evp_final = 0;

        evp_ctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(evp_ctx))
            ok = 0;

        if (ok && !TEST_true(EVP_EncryptInit_ex(evp_ctx,
                                                EVP_aes_256_cbc(),
                                                NULL, key, iv))) {
            ok = 0;
        }

        expected_ct = OPENSSL_malloc(plen + EVP_MAX_BLOCK_LENGTH);
        if (!TEST_ptr(expected_ct))
            ok = 0;

        if (ok && !TEST_true(EVP_EncryptUpdate(evp_ctx,
                                                expected_ct, &evp_len,
                                                plaintext, (int)plen))) {
            ok = 0;
        }

        if (ok && !TEST_true(EVP_EncryptFinal_ex(evp_ctx,
                                                 expected_ct + evp_len,
                                                 &evp_tmp))) {
            ok = 0;
        }
        evp_len += evp_tmp; /* total ciphertext length */

        EVP_CIPHER_CTX_free(evp_ctx);
        evp_ctx = NULL;

        /* ------------------------------------------------------------
         * 2. Encrypt via BIO_f_cipher and compare with the EVP result.
         * ------------------------------------------------------------ */
        BIO *mem_sink = NULL;
        BIO *enc_bio = NULL;
        char *bio_ct = NULL;
        long bio_ct_len = 0;

        mem_sink = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_sink))
            ok = 0;

        enc_bio = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc_bio))
            ok = 0;

        if (ok && !TEST_true(BIO_set_cipher(enc_bio,
                                            EVP_aes_256_cbc(),
                                            key, iv, 1))) {
            ok = 0;
        }

        /* Push the cipher BIO on top of the memory sink */
        if (ok)
            enc_bio = BIO_push(enc_bio, mem_sink);

        if (ok && !TEST_int_eq(BIO_write(enc_bio,
                                         plaintext, (int)plen),
                               (int)plen)) {
            ok = 0;
        }

        if (ok && !TEST_true(BIO_flush(enc_bio))) {
            ok = 0;
        }

        /* Retrieve the ciphertext from the memory BIO */
        if (ok) {
            bio_ct_len = BIO_get_mem_data(mem_sink, &bio_ct);
            if (!TEST_int_eq((int)bio_ct_len, evp_len))
                ok = 0;
            if (ok && !TEST_mem_eq(bio_ct, (size_t)bio_ct_len,
                                   expected_ct, (size_t)evp_len))
                ok = 0;
        }

        /* ------------------------------------------------------------
         * 3. Decrypt the BIO‑produced ciphertext and verify it matches
         *    the original plaintext.
         * ------------------------------------------------------------ */
        BIO *mem_src = NULL;
        BIO *dec_bio = NULL;
        unsigned char *dec_out = NULL;
        int dec_len = 0;
        int dec_tmp = 0;

        if (ok) {
            mem_src = BIO_new_mem_buf(bio_ct, (int)bio_ct_len);
            if (!TEST_ptr(mem_src))
                ok = 0;
        }

        if (ok) {
            dec_bio = BIO_new(BIO_f_cipher());
            if (!TEST_ptr(dec_bio))
                ok = 0;
        }

        if (ok && !TEST_true(BIO_set_cipher(dec_bio,
                                            EVP_aes_256_cbc(),
                                            key, iv, 0))) {
            ok = 0;
        }

        if (ok)
            dec_bio = BIO_push(dec_bio, mem_src);

        dec_out = OPENSSL_malloc(plen + EVP_MAX_BLOCK_LENGTH);
        if (!TEST_ptr(dec_out))
            ok = 0;

        if (ok && !TEST_true(BIO_read(dec_bio,
                                     dec_out, (int)plen) == (int)plen))
            ok = 0;

        /* Ensure the cipher status reports success */
        if (ok) {
            long status = BIO_ctrl(dec_bio, BIO_C_GET_CIPHER_STATUS, 0, NULL);
            if (!TEST_int_eq(status, 1))
                ok = 0;
        }

        if (ok && !TEST_mem_eq(dec_out, plen,
                               plaintext, plen))
            ok = 0;

        /* ------------------------------------------------------------
         * 4. Cleanup
         * ------------------------------------------------------------ */
        BIO_free_all(enc_bio);   /* frees both enc_bio and mem_sink */
        BIO_free_all(dec_bio);   /* frees both dec_bio and mem_src */
        OPENSSL_free(expected_ct);
        OPENSSL_free(dec_out);

        return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
