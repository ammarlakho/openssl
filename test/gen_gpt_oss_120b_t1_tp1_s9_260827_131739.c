/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s9_260827_131739.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test AES‑256‑CBC BIO filter against EVP direct encryption */
        const unsigned char key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        const unsigned char iv[16] = {
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
            0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
        };
        const unsigned char plaintext[] =
            "OpenSSL BIO cipher round‑trip test vector.";
        const int pt_len = (int)sizeof(plaintext) - 1; /* no NUL */

        /* ---- 1. Compute reference ciphertext with EVP API ---- */
        EVP_CIPHER_CTX *ref_ctx = EVP_CIPHER_CTX_new();
        unsigned char ref_ct[128];
        int ref_len = 0, ref_tmp = 0;

        if (!TEST_ptr(ref_ctx))
            return 0;
        if (!TEST_true(EVP_EncryptInit_ex(ref_ctx, EVP_aes_256_cbc(),
                                         NULL, key, iv)))
            goto err_ref;
        if (!TEST_true(EVP_EncryptUpdate(ref_ctx,
                                         ref_ct, &ref_len,
                                         plaintext, pt_len)))
            goto err_ref;
        if (!TEST_true(EVP_EncryptFinal_ex(ref_ctx,
                                           ref_ct + ref_len, &ref_tmp)))
            goto err_ref;
        ref_len += ref_tmp;

        /* ---- 2. Encrypt via BIO ---- */
        BIO *bmem_enc = BIO_new(BIO_s_mem());
        BIO *benc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(bmem_enc) || !TEST_ptr(benc))
            goto err_enc;
        if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* encrypt */
            goto err_enc;
        benc = BIO_push(benc, bmem_enc);

        if (!TEST_int_eq(BIO_write(benc, plaintext, pt_len), pt_len))
            goto err_enc;
        if (!TEST_true(BIO_flush(benc)))
            goto err_enc;

        BUF_MEM *bptr = NULL;
        if (!TEST_true(BIO_get_mem_ptr(bmem_enc, &bptr)))
            goto err_enc;
        /* bptr now holds the BIO‑produced ciphertext */
        if (!TEST_int_eq((int)bptr->length, ref_len))
            goto err_enc;
        if (!TEST_mem_eq(bptr->data, bptr->length, ref_ct, ref_len))
            goto err_enc;

        /* ---- 3. Decrypt via BIO and compare to original plaintext ---- */
        BIO *bmem_dec = BIO_new_mem_buf(bptr->data, (int)bptr->length);
        BIO *bdec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(bmem_dec) || !TEST_ptr(bdec))
            goto err_dec;
        if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* decrypt */
            goto err_dec;
        bdec = BIO_push(bdec, bmem_dec);

        unsigned char outbuf[128];
        int outlen = 0, total = 0;
        while ((outlen = BIO_read(bdec, outbuf + total,
                                 sizeof(outbuf) - total)) > 0) {
            total += outlen;
        }
        if (!TEST_int_eq(total, pt_len))
            goto err_dec;
        if (!TEST_mem_eq(outbuf, total, plaintext, pt_len))
            goto err_dec;

        /* ---- cleanup ---- */
        EVP_CIPHER_CTX_free(ref_ctx);
        BIO_free_all(benc);
        BIO_free_all(bdec);
        return 1;

    err_ref:
        EVP_CIPHER_CTX_free(ref_ctx);
        return 0;
    err_enc:
        BIO_free_all(benc);
        return 0;
    err_dec:
        BIO_free_all(bdec);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
