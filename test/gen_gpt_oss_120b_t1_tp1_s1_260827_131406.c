/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s1_260827_131406.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        /* Test BIO_f_cipher AES‑256‑CBC round‑trip */
        static const unsigned char key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        static const unsigned char iv[16] = {
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
            0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
        };
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        const size_t pt_len = sizeof(plaintext) - 1; /* omit NUL */
        unsigned char outbuf[256];
        int outlen, total;
        int ok = 0;
        BIO *mem_enc = NULL, *cipher_enc = NULL;
        BIO *mem_dec = NULL, *cipher_dec = NULL;
        char *cdata = NULL;
        long clen = 0;
        unsigned char *cdata_copy = NULL;

        /* ----- encryption side ----- */
        mem_enc = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_enc))
            goto cleanup;
        cipher_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_enc))
            goto cleanup;
        if (!TEST_true(BIO_set_cipher(cipher_enc, EVP_aes_256_cbc(),
                                    key, iv, 1)))
            goto cleanup;
        BIO_push(cipher_enc, mem_enc);
        outlen = BIO_write(cipher_enc, plaintext, (int)pt_len);
        if (!TEST_int_eq(outlen, (int)pt_len))
            goto cleanup;
        if (!TEST_true(BIO_flush(cipher_enc)))
            goto cleanup;

        /* obtain ciphertext */
        clen = BIO_get_mem_data(mem_enc, &cdata);
        if (!TEST_long_gt(clen, 0))
            goto cleanup;
        cdata_copy = OPENSSL_memdup(cdata, (size_t)clen);
        if (!TEST_ptr(cdata_copy))
            goto cleanup;

        /* ----- decryption side ----- */
        mem_dec = BIO_new_mem_buf(cdata_copy, (int)clen);
        if (!TEST_ptr(mem_dec))
            goto cleanup;
        cipher_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_dec))
            goto cleanup;
        if (!TEST_true(BIO_set_cipher(cipher_dec, EVP_aes_256_cbc(),
                                    key, iv, 0)))
            goto cleanup;
        BIO_push(cipher_dec, mem_dec);

        total = 0;
        while ((outlen = BIO_read(cipher_dec, outbuf + total,
                                 (int)(sizeof(outbuf) - total))) > 0) {
            total += outlen;
            if (total >= (int)sizeof(outbuf))
                break;
        }
        if (!TEST_int_eq(total, (int)pt_len))
            goto cleanup;
        if (!TEST_mem_eq(outbuf, total, plaintext, pt_len))
            goto cleanup;

        ok = 1; /* success */

    cleanup:
        BIO_free_all(cipher_enc);   /* frees mem_enc as well */
        BIO_free_all(cipher_dec);   /* frees mem_dec as well */
        OPENSSL_free(cdata_copy);
        return ok;
    }
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
