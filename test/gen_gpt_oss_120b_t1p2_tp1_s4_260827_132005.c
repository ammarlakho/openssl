/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s4_260827_132005.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* This test checks that the BIO cipher filter correctly encrypts and
         * decrypts data using AES‑256‑CBC, and that the ciphertext produced by
         * the BIO matches the ciphertext obtained by using the EVP API directly.
         *
         * Note: <openssl/buffer.h> is required for the BUF_MEM type used by
         * BIO_get_mem_ptr; it is not included in the stub headers. */
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();
        unsigned char key[32];
        unsigned char iv[16];
        const char plaintext[] = "The quick brown fox jumps over the lazy dog";
        size_t plaintext_len = strlen(plaintext);
        unsigned char expected_cipher[256];
        int enc_len1 = 0, enc_len2 = 0, expected_len = 0;
        EVP_CIPHER_CTX *ectx = NULL;
        BIO *mem = NULL, *enc = NULL;
        BUF_MEM *bptr = NULL;
        int ret = 0; /* 0 on failure, 1 on success */

        /* Initialise a deterministic key/IV */
        memset(key, 0x77, sizeof(key)); /* 'w' */
        memset(iv, 0x66, sizeof(iv));   /* 'f' */

        /* ----- Produce the reference ciphertext using EVP ----- */
        ectx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(ectx))
            goto done;
        if (!TEST_true(EVP_EncryptInit_ex(ectx, cipher, NULL, key, iv)))
            goto done;
        if (!TEST_true(EVP_EncryptUpdate(ectx,
                                         expected_cipher,
                                         &enc_len1,
                                         (const unsigned char *)plaintext,
                                         (int)plaintext_len)))
            goto done;
        if (!TEST_true(EVP_EncryptFinal_ex(ectx,
                                           expected_cipher + enc_len1,
                                           &enc_len2)))
            goto done;
        EVP_CIPHER_CTX_free(ectx);
        ectx = NULL;
        expected_len = enc_len1 + enc_len2;

        /* ----- Encrypt using the cipher BIO ----- */
        mem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem))
            goto done;
        enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc))
            goto done;
        if (!TEST_true(BIO_set_cipher(enc, cipher, key, iv, 1)))   /* encrypt = 1 */
            goto done;
        /* Chain: enc -> mem */
        BIO_push(enc, mem);

        if (!TEST_int_eq(BIO_write(enc, plaintext, (int)plaintext_len),
                         (int)plaintext_len))
            goto done;
        if (!TEST_true(BIO_flush(enc)))
            goto done;

        /* Retrieve the produced ciphertext from the memory BIO */
        if (!TEST_true(BIO_get_mem_ptr(mem, &bptr)))
            goto done;
        if (!TEST_int_eq(bptr->length, expected_len))
            goto done;
        if (!TEST_mem_eq(bptr->data, bptr->length,
                         expected_cipher, expected_len))
            goto done;

        /* ----- Decrypt using the cipher BIO ----- */
        {
            BIO *src = BIO_new_mem_buf(bptr->data, bptr->length);
            BIO *dec = BIO_new(BIO_f_cipher());

            if (!TEST_ptr(src) || !TEST_ptr(dec))
                goto done;
            if (!TEST_true(BIO_set_cipher(dec, cipher, key, iv, 0)))   /* decrypt = 0 */
                goto done;
            BIO_push(dec, src);

            unsigned char outbuf[256];
            int outlen, total = 0;

            while ((outlen = BIO_read(dec, outbuf + total,
                                     (int)sizeof(outbuf) - total)) > 0) {
                total += outlen;
            }
            /* Ensure the whole plaintext was recovered */
            if (!TEST_int_eq(total, (int)plaintext_len))
                goto done;
            if (!TEST_mem_eq(outbuf, total,
                             plaintext, plaintext_len))
                goto done;

            BIO_free_all(dec);
        }

        /* If we reached here all checks passed */
        ret = 1;

done:
        if (ectx != NULL)
            EVP_CIPHER_CTX_free(ectx);
        if (enc != NULL)
            BIO_free_all(enc);
        else if (mem != NULL)
            BIO_free_all(mem);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
