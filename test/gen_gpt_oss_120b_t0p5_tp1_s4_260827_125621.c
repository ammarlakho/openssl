/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p5_tp1_s4_260827_125621.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
            "The quick brown fox jumps over the lazy dog";
        const size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */
        unsigned char expected[128];
        int outlen1 = 0, outlen2 = 0, exp_len = 0;
        EVP_CIPHER_CTX *cctx = NULL;
        BIO *mem = NULL, *enc = NULL;
        BIO *mem2 = NULL, *dec = NULL;
        char *enc_data = NULL;
        long enc_len = 0;
        unsigned char outbuf[128];
        int total = 0, r = 0;
        int ret = 0; /* failure by default */

        /* ---------- Compute expected ciphertext with EVP ---------- */
        cctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(cctx))
            goto done;
        if (!TEST_true(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(),
                                          NULL, key, iv)))
            goto done;
        if (!TEST_int_gt(EVP_EncryptUpdate(cctx,
                                           expected, &outlen1,
                                           plaintext, (int)pt_len), 0))
            goto done;
        if (!TEST_int_gt(EVP_EncryptFinal_ex(cctx,
                                             expected + outlen1, &outlen2), 0))
            goto done;
        exp_len = outlen1 + outlen2;
        EVP_CIPHER_CTX_free(cctx);
        cctx = NULL;

        /* ---------- Encrypt via BIO_f_cipher ---------- */
        mem = BIO_new(BIO_s_mem());
        enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem) || !TEST_ptr(enc))
            goto done;
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                      key, iv, 1)))
            goto done;
        BIO_push(enc, mem);
        if (!TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len))
            goto done;
        if (!TEST_true(BIO_flush(enc)))
            goto done;
        enc_len = BIO_get_mem_data(mem, &enc_data);
        if (!TEST_int_eq((int)enc_len, exp_len))
            goto done;
        if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                         expected, (size_t)exp_len))
            goto done;

        /* ---------- Decrypt via BIO_f_cipher ---------- */
        mem2 = BIO_new_mem_buf(enc_data, (int)enc_len);
        dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem2) || !TEST_ptr(dec))
            goto done;
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))
            goto done;
        BIO_push(dec, mem2);
        total = 0;
        while ((r = BIO_read(dec, outbuf + total,
                            (int)(sizeof(outbuf) - total))) > 0) {
            total += r;
            if (total >= (int)sizeof(outbuf))
                break;
        }
        if (!TEST_int_eq(total, (int)pt_len))
            goto done;
        if (!TEST_mem_eq(outbuf, (size_t)total,
                         plaintext, pt_len))
            goto done;

        ret = 1; /* success */

    done:
        if (cctx)
            EVP_CIPHER_CTX_free(cctx);
        if (enc)
            BIO_free_all(enc);   /* also frees mem */
        if (dec)
            BIO_free_all(dec);   /* also frees mem2 */
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
