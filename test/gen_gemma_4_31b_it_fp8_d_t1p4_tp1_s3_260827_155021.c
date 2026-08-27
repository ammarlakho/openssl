/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p4_tp1_s3_260827_155021.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const char *plaintext = "Testing the BIO cipher filtered encryption/decryption round-trip.";
    int plain_len = (int)strlen(plaintext);
    
    BIO *bmem = NULL, *bcipher = NULL;
    unsigned char *encrypt_out = NULL;
    unsigned char *decrypt_out = NULL;
    int encrypt_len = 0;
    int decrypt_len = 0;
    int ret = 0;

    /* 1. Encryption using BIO */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((bcipher = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(bcipher, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bcipher, cipher, key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(bcipher, plaintext, plain_len) > 0))
        goto err;

    if (!TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Capture the ciphertext from the underlying memory BIO */
    encrypt_out = OPENSSL_malloc(plain_len + EVP_MAX_BLOCK_LENGTH);
    if (encrypt_out == NULL)
        goto err;

    encrypt_len = BIO_read(bmem, encrypt_out, plain_len + EVP_MAX_BLOCK_LENGTH);
    if (encrypt_len <= 0)
        goto err;

    /* 2. Verify against a reference EVP calculation (Fixed Vector Logic) */
    {
        EVP_CIPHER_CTX *ref_ctx = EVP_CIPHER_CTX_new();
        unsigned char ref_out[256];
        int ref_len = 0, tmp_len = 0;

        if (!TEST_ptr(ref_ctx))
            goto err;
        if (!TEST_true(EVP_EncryptInit_ex(ref_ctx, cipher, NULL, key, iv))) {
            EVP_CIPHER_CTX_free(ref_ctx);
            goto err;
        }
        if (!TEST_true(EVP_EncryptUpdate(ref_ctx, ref_out, &tmp_len, 
            (unsigned char *)plaintext, plain_len))) {
            EVP_CIPHER_CTX_free(ref_ctx);
            goto err;
        }
        ref_len = tmp_len;
        if (!TEST_true(EVP_EncryptFinal_ex(ref_ctx, ref_out + tmp_len, &tmp_len))) {
            EVP_CIPHER_CTX_free(ref_ctx);
            goto err;
        }
        ref_len += tmp_len;
        EVP_CIPHER_CTX_free(ref_ctx);

        if (!TEST_mem_eq(ref_out, ref_len, encrypt_out, encrypt_len))
            goto err;
    }

    /* 3. Decryption using BIO */
    {
        BIO *bmem_dec = NULL, *bcipher_dec = NULL;
        
        if (!TEST_ptr((bmem_dec = BIO_new(BIO_s_mem()))))
            goto err;
        if (!TEST_true(BIO_write(bmem_dec, encrypt_out, encrypt_len)))
            goto err;
        if (!TEST_ptr((bcipher_dec = BIO_new(BIO_f_cipher()))))
            goto err;
        if (!TEST_true(BIO_push(bcipher_dec, bmem_dec)))
            goto err;

        if (!TEST_true(BIO_set_cipher(bcipher_dec, cipher, key, iv, 0)))
            goto err;

        decrypt_out = OPENSSL_malloc(plain_len + EVP_MAX_BLOCK_LENGTH);
        if (decrypt_out == NULL)
            goto err;

        decrypt_len = BIO_read(bcipher_dec, decrypt_out, plain_len + EVP_MAX_BLOCK_LENGTH);
        if (decrypt_len <= 0)
            goto err;

        if (!TEST_mem_eq(plaintext, plain_len, decrypt_out, decrypt_len))
            goto err;

        BIO_free_all(bcipher_dec);
    }

    ret = 1;

err:
    if (bmem || bcipher)
        BIO_free_all(bcipher);
    OPENSSL_free(encrypt_out);
    OPENSSL_free(decrypt_out);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
