/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s5_260827_132546.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
         * Test the BIO cipher filter (AES‑256‑CBC) for a known
         * encrypt‑then‑decrypt round‑trip using a fixed key/IV and
         * compare the BIO‑generated ciphertext against the reference
         * EVP encryption output.
         */
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
        const unsigned char plaintext[] =
            "OpenSSL BIO cipher test data 1234567890";
        size_t pt_len = sizeof(plaintext) - 1;      /* exclude NUL */

        /* -----------------------------------------------------------------
         * Reference ciphertext using the EVP low‑level API.
         * ----------------------------------------------------------------- */
        EVP_CIPHER_CTX *ec = EVP_CIPHER_CTX_new();
        unsigned char ref_ct[256];
        int ref_len1 = 0, ref_len2 = 0, ref_ct_len = 0;

        if (!TEST_ptr(ec))
            return 0;
        if (!TEST_true(EVP_EncryptInit_ex(ec, EVP_aes_256_cbc(),
                                        NULL, key, iv)))
            goto end_ref;

        if (!TEST_true(EVP_EncryptUpdate(ec,
                ref_ct, &ref_len1,
                plaintext, (int)pt_len)))
            goto end_ref;

        if (!TEST_true(EVP_EncryptFinal_ex(ec,
                ref_ct + ref_len1, &ref_len2)))
            goto end_ref;

        ref_ct_len = ref_len1 + ref_len2;

        /* -----------------------------------------------------------------
         * Encryption through the BIO filter.
         * ----------------------------------------------------------------- */
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *enc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem) || !TEST_ptr(enc))
            goto end_ref;

        BIO_push(enc, mem);   /* enc is now the top of the chain */

        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                     key, iv, 1)))   /* 1 = encrypt */
            goto end_ref;

        if (!TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len))
            goto end_ref;

        if (!TEST_true(BIO_flush(enc)))
            goto end_ref;

        char *cipher_ptr = NULL;
        long cipher_len = BIO_get_mem_data(mem, &cipher_ptr);
        if (!TEST_long_eq(cipher_len, (long)ref_ct_len))
            goto end_ref;

        /* Copy the ciphertext out of the memory BIO before freeing it. */
        unsigned char cipher_buf[256];
        if ((size_t)cipher_len > sizeof(cipher_buf))
            goto end_ref;
        memcpy(cipher_buf, cipher_ptr, (size_t)cipher_len);

        if (!TEST_mem_eq(cipher_buf, (size_t)cipher_len,
                         ref_ct, (size_t)ref_ct_len))
            goto end_ref;

        /* -----------------------------------------------------------------
         * Decryption through a new BIO filter.
         * ----------------------------------------------------------------- */
        BIO *src = BIO_new_mem_buf(cipher_buf, (int)cipher_len);
        BIO *dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(src) || !TEST_ptr(dec))
            goto end_ref;

        BIO_push(dec, src);   /* dec reads from src */

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                     key, iv, 0)))   /* 0 = decrypt */
            goto end_ref;

        unsigned char plain_out[256];
        int rd = BIO_read(dec, plain_out, (int)sizeof(plain_out));
        if (!TEST_int_ge(rd, (int)pt_len))
            goto end_ref;

        if (!TEST_mem_eq(plain_out, (size_t)rd,
                         plaintext, pt_len))
            goto end_ref;

        /* Success – clean up and return 1. */
        EVP_CIPHER_CTX_free(ec);
        BIO_free_all(enc);
        BIO_free_all(dec);
        return 1;

    end_ref:
        EVP_CIPHER_CTX_free(ec);
        BIO_free_all(enc);
        BIO_free_all(dec);
        BIO_free_all(mem);
        BIO_free_all(src);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
