/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp0p95_fp0_s1_260827_002516.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        /* Fixed test vectors */
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
        const int plen = (int)sizeof(plaintext) - 1; /* no trailing NUL */

        /* ------------------------------------------------------------
         * 1. Compute the expected ciphertext using the EVP API.
         * ------------------------------------------------------------ */
        EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(ectx))
            return 0;

        if (!TEST_true(EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(),
                                         NULL, key, iv))) {
            EVP_CIPHER_CTX_free(ectx);
            return 0;
        }

        unsigned char *expected_ct = OPENSSL_malloc(plen + EVP_MAX_BLOCK_LENGTH);
        if (!TEST_ptr(expected_ct)) {
            EVP_CIPHER_CTX_free(ectx);
            return 0;
        }

        int outlen1 = 0, outlen2 = 0;
        if (!TEST_true(EVP_EncryptUpdate(ectx,
                                         expected_ct, &outlen1,
                                         plaintext, plen))) {
            OPENSSL_free(expected_ct);
            EVP_CIPHER_CTX_free(ectx);
            return 0;
        }
        if (!TEST_true(EVP_EncryptFinal_ex(ectx,
                                           expected_ct + outlen1, &outlen2))) {
            OPENSSL_free(expected_ct);
            EVP_CIPHER_CTX_free(ectx);
            return 0;
        }
        EVP_CIPHER_CTX_free(ectx);
        const int ct_len = outlen1 + outlen2;

        /* ------------------------------------------------------------
         * 2. Encrypt via BIO_f_cipher and compare with expected_ct.
         * ------------------------------------------------------------ */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *benc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_enc) || !TEST_ptr(benc)) {
            BIO_free_all(mem_enc);
            BIO_free_all(benc);
            OPENSSL_free(expected_ct);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                      key, iv, 1))) { /* encrypt */
            BIO_free_all(mem_enc);
            BIO_free_all(benc);
            OPENSSL_free(expected_ct);
            return 0;
        }

        BIO_push(benc, mem_enc);      /* benc -> mem_enc */
        if (!TEST_int_eq(BIO_write(benc, plaintext, plen), plen)) {
            BIO_free_all(benc);
            OPENSSL_free(expected_ct);
            return 0;
        }
        /* Ensure final block is written */
        (void)BIO_flush(benc);

        /* Read the ciphertext produced by the BIO chain */
        unsigned char *bio_ct = OPENSSL_malloc(ct_len);
        if (!TEST_ptr(bio_ct)) {
            BIO_free_all(benc);
            OPENSSL_free(expected_ct);
            return 0;
        }
        int r = BIO_read(mem_enc, bio_ct, ct_len);
        if (!TEST_int_eq(r, ct_len)) {
            BIO_free_all(benc);
            OPENSSL_free(expected_ct);
            OPENSSL_free(bio_ct);
            return 0;
        }

        /* Verify ciphertext matches the EVP‑computed one */
        if (!TEST_mem_eq(bio_ct, ct_len, expected_ct, ct_len)) {
            BIO_free_all(benc);
            OPENSSL_free(expected_ct);
            OPENSSL_free(bio_ct);
            return 0;
        }

        BIO_free_all(benc);
        OPENSSL_free(bio_ct);

        /* ------------------------------------------------------------
         * 3. Decrypt via BIO_f_cipher and verify we obtain the original plaintext.
         * ------------------------------------------------------------ */
        BIO *mem_ct = BIO_new_mem_buf(expected_ct, ct_len);
        BIO *bdec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_ct) || !TEST_ptr(bdec)) {
            BIO_free_all(mem_ct);
            BIO_free_all(bdec);
            OPENSSL_free(expected_ct);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                      key, iv, 0))) { /* decrypt */
            BIO_free_all(mem_ct);
            BIO_free_all(bdec);
            OPENSSL_free(expected_ct);
            return 0;
        }

        BIO_push(bdec, mem_ct);       /* bdec -> mem_ct */

        unsigned char *dec_out = OPENSSL_malloc(plen + EVP_MAX_BLOCK_LENGTH);
        if (!TEST_ptr(dec_out)) {
            BIO_free_all(bdec);
            OPENSSL_free(expected_ct);
            return 0;
        }

        int dec_len = 0, got;
        while ((got = BIO_read(bdec,
                               dec_out + dec_len,
                               plen + EVP_MAX_BLOCK_LENGTH - dec_len)) > 0) {
            dec_len += got;
        }
        /* BIO_read may return 0 at EOF; any negative value that is not retry is error */
        if (got < 0 && !BIO_should_retry(bdec)) {
            BIO_free_all(bdec);
            OPENSSL_free(expected_ct);
            OPENSSL_free(dec_out);
            return 0;
        }

        /* The decrypted length must equal the original plaintext length */
        if (!TEST_int_eq(dec_len, plen)) {
            BIO_free_all(bdec);
            OPENSSL_free(expected_ct);
            OPENSSL_free(dec_out);
            return 0;
        }

        if (!TEST_mem_eq(dec_out, dec_len, plaintext, plen)) {
            BIO_free_all(bdec);
            OPENSSL_free(expected_ct);
            OPENSSL_free(dec_out);
            return 0;
        }

        BIO_free_all(bdec);
        OPENSSL_free(dec_out);
        OPENSSL_free(expected_ct);
        return 1;
    }
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
