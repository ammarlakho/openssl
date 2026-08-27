/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s6_260827_132626.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test that BIO_f_cipher encrypts/decrypts correctly using
         * AES‑256‑CBC. The ciphertext produced by the BIO chain is compared
         * with the result of an equivalent EVP API call, and a decrypt BIO is
         * then used to recover the original plaintext. */
        const unsigned char key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        const unsigned char iv[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };
        const char plaintext[] =
            "OpenSSL BIO cipher test vector data for AES‑256‑CBC.";
        size_t plaintext_len = strlen(plaintext);

        /* ---------- Encrypt with BIO ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_enc))
            return 0;

        BIO *bio_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bio_enc)) {
            BIO_free(mem_enc);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(bio_enc, EVP_aes_256_cbc(),
                                      key, iv, 1))) {
            BIO_free_all(bio_enc);
            BIO_free(mem_enc);
            return 0;
        }

        bio_enc = BIO_push(bio_enc, mem_enc);

        if (!TEST_int_gt(BIO_write(bio_enc, plaintext,
                                   (int)plaintext_len), 0))
            goto fail_enc;

        if (!TEST_int_eq(BIO_flush(bio_enc), 1))
            goto fail_enc;

        /* Retrieve ciphertext from the memory BIO */
        BUF_MEM *bptr = NULL;
        BIO_get_mem_ptr(mem_enc, &bptr);
        if (!TEST_ptr(bptr))
            goto fail_enc;
        const unsigned char *cipher_bio = (const unsigned char *)bptr->data;
        size_t cipher_bio_len = (size_t)bptr->length;

        /* ---------- Encrypt with EVP (reference) ---------- */
        EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(evp_ctx))
            goto fail_enc;

        if (!TEST_true(EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(),
                                         NULL, key, iv))) {
            EVP_CIPHER_CTX_free(evp_ctx);
            goto fail_enc;
        }

        unsigned char evp_out[1024];
        int outlen1 = 0, outlen2 = 0;
        if (!TEST_true(EVP_EncryptUpdate(evp_ctx,
                         evp_out, &outlen1,
                         (const unsigned char *)plaintext,
                         (int)plaintext_len))) {
            EVP_CIPHER_CTX_free(evp_ctx);
            goto fail_enc;
        }

        if (!TEST_true(EVP_EncryptFinal_ex(evp_ctx,
                         evp_out + outlen1, &outlen2))) {
            EVP_CIPHER_CTX_free(evp_ctx);
            goto fail_enc;
        }
        EVP_CIPHER_CTX_free(evp_ctx);
        size_t evp_cipher_len = (size_t)(outlen1 + outlen2);

        /* Compare BIO ciphertext with EVP ciphertext */
        if (!TEST_size_t_eq(cipher_bio_len, evp_cipher_len))
            goto fail_enc;
        if (!TEST_mem_eq(cipher_bio, cipher_bio_len,
                        evp_out, evp_cipher_len))
            goto fail_enc;

        /* ---------- Decrypt with BIO ---------- */
        BIO *mem_dec = BIO_new_mem_buf((void *)cipher_bio,
                                      (int)cipher_bio_len);
        if (!TEST_ptr(mem_dec)) {
            BIO_free_all(bio_enc);
            return 0;
        }

        BIO *bio_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bio_dec)) {
            BIO_free(mem_dec);
            BIO_free_all(bio_enc);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(bio_dec, EVP_aes_256_cbc(),
                                      key, iv, 0))) {
            BIO_free(mem_dec);
            BIO_free_all(bio_enc);
            BIO_free_all(bio_dec);
            return 0;
        }

        bio_dec = BIO_push(bio_dec, mem_dec);

        unsigned char plain_out[1024];
        int out_total = 0, r;
        do {
            r = BIO_read(bio_dec,
                         plain_out + out_total,
                         (int)(sizeof(plain_out) - out_total));
            if (r > 0)
                out_total += r;
        } while (r > 0);

        if (!TEST_int_eq(out_total, (int)plaintext_len))
            goto fail_dec;
        if (!TEST_mem_eq(plain_out, (size_t)out_total,
                        plaintext, plaintext_len))
            goto fail_dec;

        /* Cleanup */
        BIO_free_all(bio_dec);
        BIO_free_all(bio_enc);
        return 1;

    fail_enc:
        BIO_free_all(bio_enc);
        return 0;

    fail_dec:
        BIO_free_all(bio_dec);
        BIO_free_all(bio_enc);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
