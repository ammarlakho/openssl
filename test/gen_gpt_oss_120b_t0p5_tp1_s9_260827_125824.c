/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p5_tp1_s9_260827_125824.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */

        BIO *bmem = NULL, *bcipher = NULL;
        BIO *bmem2 = NULL, *bcipher2 = NULL;
        unsigned char *enc = NULL;
        unsigned char *out = NULL;
        int ret = 0;

        /* ---------- Encryption side ---------- */
        if (!TEST_ptr(bmem = BIO_new(BIO_s_mem()))
            || !TEST_ptr(bcipher = BIO_new(BIO_f_cipher()))
            || !TEST_true(BIO_set_cipher(bcipher,
                                         EVP_aes_256_cbc(),
                                         key, iv, 1))) /* encrypt */
            goto end;

        BIO_push(bcipher, bmem);

        if (!TEST_int_eq(BIO_write(bcipher,
                                   plaintext,
                                   (int)pt_len), (int)pt_len))
            goto end;
        if (!TEST_true(BIO_flush(bcipher)))      /* finalize encryption */
            goto end;

        /* Retrieve ciphertext from the memory BIO */
        long enc_len = BIO_ctrl_pending(bmem);
        if (!TEST_int_gt(enc_len, 0))
            goto end;
        if (!TEST_ptr(enc = OPENSSL_malloc(enc_len)))
            goto end;
        if (!TEST_int_eq(BIO_read(bmem,
                                  enc,
                                  (int)enc_len), (int)enc_len))
            goto end;

        /* ---------- Decryption side ---------- */
        if (!TEST_ptr(bmem2 = BIO_new_mem_buf(enc, (int)enc_len))
            || !TEST_ptr(bcipher2 = BIO_new(BIO_f_cipher()))
            || !TEST_true(BIO_set_cipher(bcipher2,
                                         EVP_aes_256_cbc(),
                                         key, iv, 0))) /* decrypt */
            goto end;

        BIO_push(bcipher2, bmem2);

        if (!TEST_ptr(out = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH)))
            goto end;
        int out_len = BIO_read(bcipher2,
                               out,
                               (int)(pt_len + EVP_MAX_BLOCK_LENGTH));
        if (!TEST_int_gt(out_len, 0))
            goto end;
        if (!TEST_mem_eq(out, out_len, plaintext, pt_len))
            goto end;

        /* Cipher status should indicate success */
        if (!TEST_true(BIO_ctrl(bcipher2,
                                BIO_C_GET_CIPHER_STATUS,
                                0, NULL)))
            goto end;

        ret = 1;   /* all checks passed */

    end:
        BIO_free_all(bcipher);
        BIO_free_all(bcipher2);
        OPENSSL_free(enc);
        OPENSSL_free(out);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
