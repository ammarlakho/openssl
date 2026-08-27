/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s2_260827_130933.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        static const unsigned char key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        static const unsigned char iv[16] = {
            0x00, 0x01, 0x02, 0x03,
            0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f
        };
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        const int plen = (int)sizeof(plaintext) - 1;   /* no terminating NUL */

        /* ------------------------------------------------------------
         * Compute the expected ciphertext using the EVP low‑level API.
         * ------------------------------------------------------------ */
        unsigned char evp_ctxt[128];
        int evp_len = 0, tmp = 0;
        EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();

        if (!TEST_ptr(cctx))
            return 0;
        if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(),
                                          NULL, key, iv)))
            goto err;
        if (!TEST_true(EVP_EncryptUpdate(cctx, evp_ctxt, &tmp,
                                         plaintext, plen)))
            goto err;
        evp_len = tmp;
        if (!TEST_true(EVP_EncryptFinal_ex(cctx, evp_ctxt + evp_len, &tmp)))
            goto err;
        evp_len += tmp;
        EVP_CIPHER_CTX_free(cctx);
        cctx = NULL;

        /* ------------------------------------------------------------
         * Encrypt using the BIO cipher filter.
         * ------------------------------------------------------------ */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *benc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_enc) || !TEST_ptr(benc))
            return 0;
        if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* encrypt */
            goto err;

        BIO_push(benc, mem_enc);
        if (!TEST_int_eq(BIO_write(benc, plaintext, plen), plen))
            goto err;
        if (!TEST_true(BIO_flush(benc)))
            goto err;

        /* Retrieve the ciphertext produced by the BIO chain */
        BUF_MEM *bptr = NULL;
        BIO_get_mem_ptr(mem_enc, &bptr);
        if (!TEST_ptr(bptr))
            goto err;
        if (!TEST_int_eq(bptr->length, evp_len))
            goto err;
        if (!TEST_mem_eq(bptr->data, bptr->length, evp_ctxt, evp_len))
            goto err;

        /* Keep a copy of the ciphertext because the memory BIO will be freed */
        unsigned char *ciphertext = OPENSSL_malloc(bptr->length);
        if (!TEST_ptr(ciphertext))
            goto err;
        memcpy(ciphertext, bptr->data, bptr->length);
        int ciphertext_len = bptr->length;

        BIO_free_all(benc);   /* also frees mem_enc */

        /* ------------------------------------------------------------
         * Decrypt using the BIO cipher filter and verify round‑trip.
         * ------------------------------------------------------------ */
        BIO *mem_in = BIO_new_mem_buf(ciphertext, ciphertext_len);
        BIO *bdec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_in) || !TEST_ptr(bdec))
            goto err;
        if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* decrypt */
            goto err;

        BIO_push(bdec, mem_in);
        unsigned char outbuf[128];
        int outlen = 0, r;

        while ((r = BIO_read(bdec, outbuf + outlen,
                            sizeof(outbuf) - outlen)) > 0) {
            outlen += r;
            if (outlen >= (int)sizeof(outbuf))
                break;
        }

        if (!TEST_int_eq(outlen, plen))
            goto err;
        if (!TEST_mem_eq(outbuf, outlen, plaintext, plen))
            goto err;

        BIO_free_all(bdec);
        OPENSSL_free(ciphertext);
        return 1;

    err:
        if (cctx != NULL)
            EVP_CIPHER_CTX_free(cctx);
        BIO_free_all(benc);
        BIO_free_all(bdec);
        OPENSSL_free(ciphertext);
        return 0;
    }
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
