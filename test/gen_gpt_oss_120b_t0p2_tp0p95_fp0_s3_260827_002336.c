/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp0p95_fp0_s3_260827_002336.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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

        /* ---------- Encryption ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_enc))
            return 0;
        BIO *enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc)) {
            BIO_free(mem_enc);
            return 0;
        }
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                    key, iv, 1))) {
            BIO_free_all(enc);
            BIO_free(mem_enc);
            return 0;
        }
        BIO_push(enc, mem_enc);

        if (!TEST_int_eq(BIO_write(enc, plaintext, (int)pt_len), (int)pt_len)) {
            BIO_free_all(enc);
            return 0;
        }
        if (!TEST_true(BIO_flush(enc))) {
            BIO_free_all(enc);
            return 0;
        }

        /* Get ciphertext from the memory BIO */
        char *cipher_ptr = NULL;
        long cipher_len = BIO_get_mem_data(mem_enc, &cipher_ptr);
        if (!TEST_int_gt(cipher_len, 0)) {
            BIO_free_all(enc);
            return 0;
        }
        unsigned char *cipher = OPENSSL_malloc(cipher_len);
        if (!TEST_ptr(cipher)) {
            BIO_free_all(enc);
            return 0;
        }
        memcpy(cipher, cipher_ptr, cipher_len);
        BIO_free_all(enc); /* frees both enc and mem_enc */

        /* ---------- Decryption ---------- */
        BIO *mem_dec = BIO_new_mem_buf(cipher, (int)cipher_len);
        if (!TEST_ptr(mem_dec)) {
            OPENSSL_free(cipher);
            return 0;
        }
        BIO *dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec)) {
            BIO_free(mem_dec);
            OPENSSL_free(cipher);
            return 0;
        }
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                    key, iv, 0))) {
            BIO_free_all(dec);
            BIO_free(mem_dec);
            OPENSSL_free(cipher);
            return 0;
        }
        BIO_push(dec, mem_dec);

        unsigned char *out = OPENSSL_malloc(pt_len);
        if (!TEST_ptr(out)) {
            BIO_free_all(dec);
            OPENSSL_free(cipher);
            return 0;
        }
        int read_total = 0;
        while (read_total < (int)pt_len) {
            int r = BIO_read(dec, out + read_total,
                             (int)(pt_len - read_total));
            if (r <= 0)
                break;
            read_total += r;
        }
        int ok = TEST_int_eq(read_total, (int)pt_len) &&
                 TEST_mem_eq(out, pt_len, plaintext, pt_len);

        BIO_free_all(dec);
        OPENSSL_free(cipher);
        OPENSSL_free(out);
        return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
