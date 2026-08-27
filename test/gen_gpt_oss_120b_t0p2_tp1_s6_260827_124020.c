/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp1_s6_260827_124020.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
static int test_bio_enc_generated(void)
{
    /* Key and IV for AES‑256‑CBC */
    static const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    /* Plain‑text */
    static const unsigned char plaintext[] =
        "OpenSSL BIO cipher test vector";
    const int pt_len = (int)sizeof(plaintext) - 1;

    /* ------------------------------------------------------------
     * 1. Produce the expected ciphertext with the EVP API.
     * ------------------------------------------------------------ */
    unsigned char exp_ct[128];
    int exp_len = 0, outlen = 0;
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();

    if (!TEST_ptr(c))
        return 0;
    if (!TEST_int_eq(EVP_EncryptInit_ex(c, EVP_aes_256_cbc(),
                                      NULL, key, iv), 1))
        goto err_evpc;
    if (!TEST_int_eq(EVP_EncryptUpdate(c, exp_ct, &outlen,
                                      plaintext, pt_len), 1))
        goto err_evpc;
    exp_len = outlen;
    if (!TEST_int_eq(EVP_EncryptFinal_ex(c, exp_ct + exp_len, &outlen), 1))
        goto err_evpc;
    exp_len += outlen;

    /* ------------------------------------------------------------
     * 2. Encrypt via BIO_f_cipher and compare with the EVP result.
     * ------------------------------------------------------------ */
    {
        BIO *mem = BIO_new(BIO_s_mem());
        BIO *benc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem) || !TEST_ptr(benc))
            goto err_bio;

        if (!TEST_int_eq(BIO_set_cipher(benc,
                                        EVP_aes_256_cbc(),
                                        key, iv, 1), 1))
            goto err_bio;

        BIO_push(benc, mem);

        if (!TEST_int_eq(BIO_write(benc, plaintext, pt_len), pt_len))
            goto err_bio;
        if (!TEST_int_eq(BIO_flush(benc), 1))
            goto err_bio;

        /* Retrieve ciphertext from the memory BIO */
        char *cipher_data = NULL;
        long cipher_len = BIO_get_mem_data(mem, &cipher_data);

        if (!TEST_int_eq((int)cipher_len, exp_len))
            goto err_bio;
        if (!TEST_mem_eq(cipher_data, (size_t)cipher_len,
                         exp_ct, (size_t)exp_len))
            goto err_bio;

        /* --------------------------------------------------------
         * 3. Decrypt the ciphertext via BIO_f_cipher and verify.
         * -------------------------------------------------------- */
        {
            BIO *mem_in = BIO_new_mem_buf(cipher_data, (int)cipher_len);
            BIO *bdec   = BIO_new(BIO_f_cipher());

            if (!TEST_ptr(mem_in) || !TEST_ptr(bdec))
                goto err_bio2;

            if (!TEST_int_eq(BIO_set_cipher(bdec,
                                            EVP_aes_256_cbc(),
                                            key, iv, 0), 1))
                goto err_bio2;

            BIO_push(bdec, mem_in);

            unsigned char outbuf[128];
            int total = 0, r;

            while ((r = BIO_read(bdec, outbuf + total,
                                (int)sizeof(outbuf) - total)) > 0) {
                total += r;
                if (total == (int)sizeof(outbuf))
                    break;
            }

            if (!TEST_int_eq(total, pt_len))
                goto err_bio2;
            if (!TEST_mem_eq(outbuf, (size_t)total,
                             plaintext, (size_t)pt_len))
                goto err_bio2;

            BIO_free_all(bdec);
        }

        BIO_free_all(benc);
    }

    EVP_CIPHER_CTX_free(c);
    return 1;

err_bio2:
    BIO_free_all(bdec);
err_bio:
    BIO_free_all(benc);
    BIO_free_all(mem);
err_evpc:
    EVP_CIPHER_CTX_free(c);
    return 0;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
