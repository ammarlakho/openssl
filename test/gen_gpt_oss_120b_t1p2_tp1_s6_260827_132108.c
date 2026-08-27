/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s6_260827_132108.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        unsigned char key[32] = {0};
        unsigned char iv[16] = {0};
        const unsigned char plaintext[] = "OpenSSL BIO Cipher Test Vector";
        int ptlen = (int)sizeof(plaintext) - 1;          /* exclude NUL */

        /* -----------------------------------------------------------------
         * Compute the expected ciphertext using the EVP API (reference vector)
         * ----------------------------------------------------------------- */
        unsigned char expected_ct[128];
        int outlen1 = 0, outlen2 = 0;
        EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();

        ok = ok && TEST_ptr(enc_ctx);
        ok = ok && EVP_CipherInit_ex(enc_ctx, cipher, NULL, key, iv, 1);
        ok = ok && EVP_CipherUpdate(enc_ctx,
                                    expected_ct, &outlen1,
                                    plaintext, ptlen);
        ok = ok && EVP_CipherFinal_ex(enc_ctx,
                                    expected_ct + outlen1, &outlen2);
        EVP_CIPHER_CTX_free(enc_ctx);

        int exp_len = outlen1 + outlen2;

        /* -----------------------------------------------------------------
         * Encrypt using BIO_f_cipher and a memory BIO
         * ----------------------------------------------------------------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *bio_enc = BIO_new(BIO_f_cipher());

        ok = ok && TEST_ptr(mem_enc);
        ok = ok && TEST_ptr(bio_enc);

        BIO_push(bio_enc, mem_enc);

        ok = ok && BIO_set_cipher(bio_enc, cipher, key, iv, 1);
        ok = ok && BIO_write(bio_enc, (const char *)plaintext, ptlen) == ptlen;
        ok = ok && BIO_flush(bio_enc) == 1;   /* flush = finalize */

        /* Retrieve the ciphertext from the memory BIO */
        BUF_MEM *bptr = NULL;                 /* <openssl/buffer.h> is pulled in via <openssl/bio.h> */
        ok = ok && BIO_get_mem_ptr(mem_enc, &bptr) > 0;
        ok = ok && TEST_int_eq(bptr->length, exp_len);
        ok = ok && TEST_mem_eq(bptr->data, bptr->length,
                               expected_ct, exp_len);

        /* -----------------------------------------------------------------
         * Decrypt the data back using BIO_f_cipher and a memory BIO
         * ----------------------------------------------------------------- */
        BIO *mem_dec = BIO_new_mem_buf(bptr->data, (int)bptr->length);
        BIO *bio_dec = BIO_new(BIO_f_cipher());

        ok = ok && TEST_ptr(mem_dec);
        ok = ok && TEST_ptr(bio_dec);

        BIO_push(bio_dec, mem_dec);

        ok = ok && BIO_set_cipher(bio_dec, cipher, key, iv, 0);

        unsigned char outbuf[128];
        int outlen = 0, r;
        while ((r = BIO_read(bio_dec, outbuf + outlen,
                            (int)sizeof(outbuf) - outlen)) > 0) {
            outlen += r;
        }
        ok = ok && TEST_int_eq(outlen, ptlen);
        ok = ok && TEST_mem_eq(outbuf, outlen, plaintext, ptlen);

        /* Cleanup */
        BIO_free_all(bio_enc);   /* also frees mem_enc */
        BIO_free_all(bio_dec);   /* also frees mem_dec */

        return ok ? 1 : 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
