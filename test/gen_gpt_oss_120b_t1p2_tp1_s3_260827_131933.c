/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s3_260827_131933.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        /* Test data: 32‑byte plaintext, 32‑byte key, 16‑byte IV */
        unsigned char key[32];
        unsigned char iv[16];
        unsigned char plaintext[32];
        unsigned char outbuf[64];
        int i;
        int ret = 0;          /* assume failure */
        BIO *mem_enc = NULL, *cipher_enc = NULL;
        BIO *mem_dec = NULL, *cipher_dec = NULL;
        const unsigned char *ciphertext;
        long ct_len;
        int out_len = 0, r;

        /* initialise deterministic test vectors */
        for (i = 0; i < 32; i++) {
            key[i] = (unsigned char)i;               /* 0x00‑0x1f */
            if (i < 16)
                iv[i] = (unsigned char)i;           /* 0x00‑0x0f */
            plaintext[i] = (unsigned char)(i + 0x55);/* arbitrary payload */
        }

        /* ---------- encryption ---------- */
        mem_enc = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_enc))
            goto end;
        cipher_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_enc))
            goto end;
        if (!TEST_true(BIO_set_cipher(cipher_enc,
                                      EVP_aes_256_cbc(),
                                      key, iv, 1)))      /* encrypt */
            goto end;

        /* push the filter in front of the memory sink */
        BIO_push(cipher_enc, mem_enc);

        if (!TEST_int_eq(BIO_write(cipher_enc, plaintext,
                                   sizeof(plaintext)), (int)sizeof(plaintext)))
            goto end;
        if (!TEST_int_gt(BIO_flush(cipher_enc), 0))
            goto end;

        /* retrieve the ciphertext from the memory BIO */
        ct_len = BIO_get_mem_data(mem_enc, &ciphertext);
        if (!TEST_true(ct_len > 0))
            goto end;

        /* ---------- decryption ---------- */
        mem_dec = BIO_new_mem_buf(ciphertext, ct_len);
        if (!TEST_ptr(mem_dec))
            goto end;
        cipher_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_dec))
            goto end;
        if (!TEST_true(BIO_set_cipher(cipher_dec,
                                      EVP_aes_256_cbc(),
                                      key, iv, 0)))      /* decrypt */
            goto end;

        BIO_push(cipher_dec, mem_dec);

        /* read all decrypted data */
        while ((r = BIO_read(cipher_dec,
                             outbuf + out_len,
                             sizeof(outbuf) - out_len)) > 0) {
            out_len += r;
            if (out_len >= (int)sizeof(outbuf))
                break; /* safety */
        }

        /* ensure we got the exact original length */
        if (!TEST_int_eq(out_len, (int)sizeof(plaintext)))
            goto end;
        if (!TEST_mem_eq(outbuf, out_len, plaintext, sizeof(plaintext)))
            goto end;

        /* all checks passed */
        ret = 1;

    end:
        BIO_free_all(cipher_enc);
        BIO_free_all(cipher_dec);
        BIO_free_all(mem_enc);
        BIO_free_all(mem_dec);
        return ret;
    }
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
