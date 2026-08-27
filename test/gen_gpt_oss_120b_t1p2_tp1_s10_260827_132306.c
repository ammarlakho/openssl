/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s10_260827_132306.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /*
         * Test BIO_f_cipher using AES‑256‑CBC.  The test encrypts a known
         * plaintext with EVP_* functions, then encrypts the same data using a
         * cipher BIO and checks that the ciphertexts match.  Afterwards the
         * ciphertext is fed through a second cipher BIO set to decrypt mode and
         * the result is compared with the original plaintext.
         */
        const unsigned char key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        const unsigned char iv[16] = {
            0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
            0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
        };
        const char *plaintext = "The quick brown fox jumps over the lazy dog";
        const size_t plain_len = strlen(plaintext);
        unsigned char evp_ctext[128];
        int evp_len1 = 0, evp_len2 = 0, evp_ctext_len = 0;
        EVP_CIPHER_CTX *cctx = NULL;
        BIO *mem = NULL, *benc = NULL;
        BIO *src = NULL, *bdec = NULL;
        BUF_MEM *bptr = NULL;
        unsigned char dec_buf[128];
        int dec_len = 0, total_dec = 0, ret = 0;

        /* ---- EVP reference encryption ---- */
        cctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(cctx))
            goto err_cleanup;
        if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(),
                                         NULL, key, iv)))
            goto err_cleanup;
        if (!TEST_true(EVP_EncryptUpdate(cctx,
                                         evp_ctext, &evp_len1,
                                         (const unsigned char *)plaintext,
                                         (int)plain_len)))
            goto err_cleanup;
        if (!TEST_true(EVP_EncryptFinal_ex(cctx,
                                           evp_ctext + evp_len1, &evp_len2)))
            goto err_cleanup;
        evp_ctext_len = evp_len1 + evp_len2;
        EVP_CIPHER_CTX_free(cctx);
        cctx = NULL;

        /* ---- BIO encrypt ---- */
        mem = BIO_new(BIO_s_mem());
        benc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem) || !TEST_ptr(benc))
            goto err_cleanup;
        BIO_push(benc, mem);
        if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                     key, iv, 1)))
            goto err_cleanup;
        if (!TEST_int_eq(BIO_write(benc, plaintext, (int)plain_len),
                         (int)plain_len))
            goto err_cleanup;
        if (!TEST_true(BIO_flush(benc)))
            goto err_cleanup;

        BIO_get_mem_ptr(mem, &bptr);
        if (!TEST_int_eq((int)bptr->length, evp_ctext_len))
            goto err_cleanup;
        if (!TEST_mem_eq(bptr->data, evp_ctext_len,
                         evp_ctext, evp_ctext_len))
            goto err_cleanup;

        /* ---- BIO decrypt ---- */
        src = BIO_new_mem_buf(bptr->data, (int)bptr->length);
        bdec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(src) || !TEST_ptr(bdec))
            goto err_cleanup;
        BIO_push(bdec, src);
        if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                     key, iv, 0)))
            goto err_cleanup;

        /* Read the whole decrypted output */
        while ((dec_len = BIO_read(bdec,
                                  dec_buf + total_dec,
                                  (int)sizeof(dec_buf) - total_dec)) > 0) {
            total_dec += dec_len;
        }
        if (!TEST_int_eq(total_dec, (int)plain_len))
            goto err_cleanup;
        if (!TEST_mem_eq(dec_buf, plain_len,
                         plaintext, plain_len))
            goto err_cleanup;

        /* All checks passed */
        ret = 1;

    err_cleanup:
        if (cctx != NULL)
            EVP_CIPHER_CTX_free(cctx);
        BIO_free_all(benc);
        BIO_free_all(bdec);
        /* mem and src are freed by BIO_free_all above */
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
