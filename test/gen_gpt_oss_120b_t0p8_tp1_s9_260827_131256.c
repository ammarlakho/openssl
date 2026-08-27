/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s9_260827_131256.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test AES‑256‑CBC encryption/decryption using the BIO_f_cipher filter.
         * The test encrypts a known plaintext with a known key/IV using the
         * EVP API to obtain a reference ciphertext, then repeats the encryption
         * through a BIO chain and checks that the output matches the reference.
         * Finally the ciphertext is fed through a decrypting BIO chain and the
         * resulting plaintext is compared with the original data. */
        static const unsigned char key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        static const unsigned char iv[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };
        static const unsigned char plaintext[] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
        };
        const int pt_len = sizeof(plaintext);
        unsigned char ref_ct[64];
        int ref_len = 0, outlen = 0;
        EVP_CIPHER_CTX *ref_ctx = NULL;
        BIO *bmem = NULL, *bciph = NULL, *chain = NULL;
        char *mem_data = NULL;
        long mem_len = 0;
        unsigned char dec_buf[64];
        int dec_len = 0;

        /* -----------------------------------------------------------------
         * 1. Build reference ciphertext using EVP API (no BIO involvement)
         * ----------------------------------------------------------------- */
        ref_ctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(ref_ctx))
            return 0;
        if (!TEST_true(EVP_CipherInit_ex(ref_ctx, EVP_aes_256_cbc(),
                                         NULL, key, iv, 1)))
            goto err;
        if (!TEST_true(EVP_CipherUpdate(ref_ctx, ref_ct, &outlen,
                                        plaintext, pt_len)))
            goto err;
        ref_len = outlen;
        if (!TEST_true(EVP_CipherFinal_ex(ref_ctx, ref_ct + outlen, &outlen)))
            goto err;
        ref_len += outlen;
        EVP_CIPHER_CTX_free(ref_ctx);
        ref_ctx = NULL;

        /* -----------------------------------------------------------------
         * 2. Encrypt via BIO chain and compare with reference ciphertext
         * ----------------------------------------------------------------- */
        bmem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(bmem))
            return 0;
        bciph = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bciph))
            goto err;
        if (!TEST_true(BIO_set_cipher(bciph, EVP_aes_256_cbc(),
                                      key, iv, 1)))
            goto err;
        chain = BIO_push(bciph, bmem);
        if (!TEST_int_eq(BIO_write(chain, plaintext, pt_len), pt_len))
            goto err;
        if (!TEST_true(BIO_flush(chain)))
            goto err;

        mem_len = BIO_get_mem_data(bmem, &mem_data);
        if (!TEST_int_eq(mem_len, ref_len))
            goto err;
        if (!TEST_mem_eq(mem_data, (size_t)mem_len,
                         ref_ct, (size_t)ref_len))
            goto err;

        /* -----------------------------------------------------------------
         * 3. Decrypt the ciphertext via a new BIO chain and verify plaintext
         * ----------------------------------------------------------------- */
        /* Create a read‑only BIO that contains the ciphertext */
        BIO *bmem_in = BIO_new_mem_buf(mem_data, (int)mem_len);
        if (!TEST_ptr(bmem_in))
            goto err;
        BIO *bciph_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bciph_dec))
            goto err;
        if (!TEST_true(BIO_set_cipher(bciph_dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* decrypt */
            goto err;
        BIO *dec_chain = BIO_push(bciph_dec, bmem_in);
        dec_len = BIO_read(dec_chain, dec_buf, sizeof(dec_buf));
        if (!TEST_int_gt(dec_len, 0))
            goto err;
        if (!TEST_mem_eq(dec_buf, (size_t)dec_len,
                         plaintext, (size_t)pt_len))
            goto err;

        /* Clean up and succeed */
        BIO_free_all(chain);
        BIO_free_all(dec_chain);
        return 1;

    err:
        if (ref_ctx)
            EVP_CIPHER_CTX_free(ref_ctx);
        BIO_free_all(chain);
        BIO_free_all(dec_chain);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
