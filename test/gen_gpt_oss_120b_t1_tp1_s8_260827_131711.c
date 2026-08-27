/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s8_260827_131711.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
            /* Prepare key, IV and test data */
            unsigned char key[32] = {0};
            unsigned char iv[16] = {0};
            const char plaintext[] = "OpenSSL BIO cipher round‑trip test vector";
            size_t pt_len = strlen(plaintext);
            int i;

            /* -----------------------------------------------------------------
             * Encrypt the plaintext using a BIO chain: cipher BIO -> memory BIO.
             * ----------------------------------------------------------------- */
            BIO *mem_enc = BIO_new(BIO_s_mem());
            BIO *cipher_enc = BIO_new(BIO_f_cipher());
            unsigned char *ciphertext = NULL;
            long c_len = 0;
            int ret;

            if (!TEST_ptr(mem_enc) || !TEST_ptr(cipher_enc))
                goto err;

            /* Initialise the cipher BIO for encryption (1 = encrypt) */
            if (!TEST_true(BIO_set_cipher(cipher_enc,
                                          EVP_aes_256_cbc(),
                                          key, iv, 1)))
                goto err;

            /* Push the memory BIO underneath the cipher BIO */
            BIO_push(cipher_enc, mem_enc);

            /* Write the whole plaintext */
            ret = BIO_write(cipher_enc, plaintext, (int)pt_len);
            if (!TEST_int_eq(ret, (int)pt_len))
                goto err;

            /* Flush to force final block processing */
            if (!TEST_true(BIO_flush(cipher_enc)))
                goto err;

            /* Retrieve the ciphertext from the memory BIO */
            c_len = BIO_ctrl_pending(mem_enc);
            if (!TEST_long_gt(c_len, 0))
                goto err;

            ciphertext = (unsigned char *)OPENSSL_malloc((size_t)c_len);
            if (!TEST_ptr(ciphertext))
                goto err;

            ret = BIO_read(mem_enc, ciphertext, (int)c_len);
            if (!TEST_int_eq(ret, (int)c_len))
                goto err;

            /* -----------------------------------------------------------------
             * Decrypt the ciphertext using a new BIO chain:
             * memory BIO (containing ciphertext) -> cipher BIO (decrypt).
             * ----------------------------------------------------------------- */
            BIO *mem_dec = BIO_new_mem_buf(ciphertext, (int)c_len);
            BIO *cipher_dec = BIO_new(BIO_f_cipher());
            unsigned char outbuf[256];
            size_t total = 0;
            int r;

            if (!TEST_ptr(mem_dec) || !TEST_ptr(cipher_dec))
                goto err;

            /* Initialise the cipher BIO for decryption (0 = decrypt) */
            if (!TEST_true(BIO_set_cipher(cipher_dec,
                                          EVP_aes_256_cbc(),
                                          key, iv, 0)))
                goto err;

            /* Push the decrypt BIO on top of the memory BIO containing ciphertext */
            BIO_push(cipher_dec, mem_dec);

            /* Read back the decrypted data */
            while (total < pt_len) {
                r = BIO_read(cipher_dec,
                             outbuf + total,
                             (int)(pt_len - total));
                if (!TEST_int_gt(r, 0))
                    goto err;
                total += (size_t)r;
            }

            /* Verify that the decrypted output matches the original plaintext */
            if (!TEST_mem_eq(outbuf, pt_len, plaintext, pt_len))
                goto err;

            /* Clean up */
            BIO_free_all(cipher_enc);   /* also frees mem_enc */
            BIO_free_all(cipher_dec);   /* also frees mem_dec */
            OPENSSL_free(ciphertext);
            return 1;

        err:
            BIO_free_all(cipher_enc);
            BIO_free_all(cipher_dec);
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
