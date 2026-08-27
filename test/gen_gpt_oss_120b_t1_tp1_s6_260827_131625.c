/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s6_260827_131625.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        int ok = 1;
        const unsigned char key[32] = { 0 };
        const unsigned char iv[16] = { 0 };
        const char *plaintext = "OpenSSL BIO encryption test vector.";
        size_t pt_len = strlen(plaintext);
        unsigned char *enc_buf = NULL;
        long enc_len = 0;

        /* ---------- Encryption side ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *cipher_enc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_enc) || !TEST_ptr(cipher_enc))
            return 0;

        if (!TEST_true(BIO_set_cipher(cipher_enc,
                                      EVP_aes_256_cbc(),
                                      key, iv, 1))) {
            ok = 0;
            goto enc_cleanup;
        }

        /* Push the cipher BIO on top of the memory BIO */
        BIO *enc_top = BIO_push(cipher_enc, mem_enc);

        if (!TEST_int_eq(BIO_write(enc_top, plaintext, (int)pt_len), (int)pt_len))
            ok = 0;
        if (!TEST_true(BIO_flush(enc_top)))
            ok = 0;

        /* Extract the ciphertext from the underlying memory BIO */
        enc_len = BIO_get_mem_data(mem_enc, &enc_buf);
        if (!TEST_int_gt(enc_len, 0))
            ok = 0;

        /* Make a private copy before freeing the encryption chain */
        unsigned char *ciphertext = OPENSSL_malloc(enc_len);
        if (!TEST_ptr(ciphertext))
            ok = 0;
        else
            memcpy(ciphertext, enc_buf, (size_t)enc_len);

    enc_cleanup:
        /* Free the encryption BIO chain (does NOT free ciphertext copy) */
        BIO_free_all(enc_top);

        if (!ok) {
            OPENSSL_free(ciphertext);
            return 0;
        }

        /* ---------- Decryption side ---------- */
        BIO *mem_dec = BIO_new_mem_buf(ciphertext, (int)enc_len);
        BIO *cipher_dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_dec) || !TEST_ptr(cipher_dec)) {
            ok = 0;
            goto dec_cleanup;
        }

        if (!TEST_true(BIO_set_cipher(cipher_dec,
                                      EVP_aes_256_cbc(),
                                      key, iv, 0))) {
            ok = 0;
            goto dec_cleanup;
        }

        BIO *dec_top = BIO_push(cipher_dec, mem_dec);

        unsigned char outbuf[256];
        int outlen = BIO_read(dec_top, outbuf, sizeof(outbuf));

        if (!TEST_int_ge(outlen, (int)pt_len))
            ok = 0;
        else if (!TEST_mem_eq(outbuf, pt_len, plaintext, pt_len))
            ok = 0;

    dec_cleanup:
        BIO_free_all(dec_top);
        OPENSSL_free(ciphertext);
        return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
