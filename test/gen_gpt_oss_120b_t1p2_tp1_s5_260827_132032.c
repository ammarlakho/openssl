/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s5_260827_132032.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        const unsigned char key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        const unsigned char iv[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };
        const unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog";
        const size_t pt_len = sizeof(plaintext) - 1;
        unsigned char evp_ct[128];
        int evp_ct_len = 0, len;
        int ret = 0; /* will become 1 on success */
        EVP_CIPHER_CTX *evp = NULL;
        BIO *bmem = NULL, *bcipher = NULL;
        BIO *bmem2 = NULL, *bcipher2 = NULL;
        unsigned char ct_copy[128];
        size_t ct_len = 0;
        BUF_MEM *bptr = NULL;
        unsigned char out[128];
        int outlen;

        /* --- Compute expected ciphertext with EVP --- */
        evp = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(evp))
            goto err;
        if (!TEST_true(EVP_EncryptInit_ex(evp, EVP_aes_256_cbc(), NULL, key, iv))
            goto err;
        if (!TEST_true(EVP_EncryptUpdate(evp, evp_ct, &len, plaintext, (int)pt_len)))
            goto err;
        evp_ct_len = len;
        if (!TEST_true(EVP_EncryptFinal_ex(evp, evp_ct + evp_ct_len, &len)))
            goto err;
        evp_ct_len += len;
        EVP_CIPHER_CTX_free(evp);
        evp = NULL;

        /* --- Encrypt through BIO_f_cipher --- */
        bmem = BIO_new(BIO_s_mem());
        bcipher = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bmem) || !TEST_ptr(bcipher))
            goto err;
        if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 1)))
            goto err;
        bcipher = BIO_push(bcipher, bmem);
        if (BIO_write(bcipher, plaintext, (int)pt_len) <= 0)
            goto err;
        if (!TEST_true(BIO_flush(bcipher)))
            goto err;

        /* retrieve ciphertext from the memory BIO */
        BIO_get_mem_ptr(bmem, &bptr);
        if (!TEST_int_eq(bptr->length, evp_ct_len))
            goto err;
        if (!TEST_mem_eq(bptr->data, bptr->length, evp_ct, evp_ct_len))
            goto err;

        /* keep a copy because we will free the BIO chain later */
        ct_len = (size_t)bptr->length;
        memcpy(ct_copy, bptr->data, ct_len);

        /* clean up the encrypt chain */
        BIO_free_all(bcipher);
        bcipher = NULL;
        bmem = NULL;

        /* --- Decrypt through BIO_f_cipher --- */
        bmem2 = BIO_new_mem_buf(ct_copy, (int)ct_len);
        bcipher2 = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bmem2) || !TEST_ptr(bcipher2))
            goto err;
        if (!TEST_true(BIO_set_cipher(bcipher2, EVP_aes_256_cbc(), key, iv, 0)))
            goto err;
        bcipher2 = BIO_push(bcipher2, bmem2);
        outlen = BIO_read(bcipher2, out, sizeof(out));
        if (!TEST_int_gt(outlen, 0))
            goto err;
        if (!TEST_int_eq(outlen, (int)pt_len))
            goto err;
        if (!TEST_mem_eq(out, outlen, plaintext, pt_len))
            goto err;

        ret = 1; /* success */

    err:
        BIO_free_all(bcipher2);
        BIO_free_all(bcipher);
        EVP_CIPHER_CTX_free(evp);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
