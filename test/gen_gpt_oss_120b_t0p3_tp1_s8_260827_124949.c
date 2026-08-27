/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p3_tp1_s8_260827_124949.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test vector: AES‑256‑CBC with zero key/IV and known plaintext.
         * The test verifies that the BIO_f_cipher filter produces the same
         * ciphertext as the EVP API and that a subsequent decryption round‑trip
         * yields the original plaintext. */
        const unsigned char key[32] = {0};
        const unsigned char iv[16] = {0};
        const unsigned char plaintext[] = "OpenSSL Test";
        const int plen = (int)sizeof(plaintext) - 1; /* exclude NUL */
        unsigned char evp_ctxt[64];
        unsigned char bio_ctxt[64];
        unsigned char dec_plain[64];
        int evp_len = 0, evp_fin = 0;
        int bio_len = 0, dec_len = 0;
        int ret = 0;
        EVP_CIPHER_CTX *ctx = NULL;
        BIO *src = NULL, *enc = NULL, *dec = NULL, *src2 = NULL;
        int i, n;

        /* ---------- Compute expected ciphertext using EVP API ---------- */
        ctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(ctx))
            goto end;
        if (!TEST_true(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),
                                          NULL, key, iv)))
            goto end;
        if (!TEST_true(EVP_EncryptUpdate(ctx,
                                          evp_ctxt, &evp_len,
                                          plaintext, plen)))
            goto end;
        if (!TEST_true(EVP_EncryptFinal_ex(ctx,
                                           evp_ctxt + evp_len, &evp_fin)))
            goto end;
        evp_len += evp_fin; /* total ciphertext length */

        /* ---------- Encrypt using BIO_f_cipher ---------- */
        src = BIO_new_mem_buf(plaintext, plen);
        if (!TEST_ptr(src))
            goto end;
        enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc))
            goto end;
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                      key, iv, 1)))   /* 1 = encrypt */
            goto end;
        BIO_push(enc, src);

        /* Read all ciphertext from the filter */
        bio_len = 0;
        while ((i = BIO_read(enc, bio_ctxt + bio_len,
                             (int)sizeof(bio_ctxt) - bio_len)) > 0) {
            bio_len += i;
            if (bio_len == (int)sizeof(bio_ctxt))
                break; /* should never happen for this test */
        }
        if (!TEST_int_eq(BIO_should_retry(enc), 0))
            goto end;
        if (!TEST_int_eq(bio_len, evp_len))
            goto end;
        if (!TEST_mem_eq(bio_ctxt, bio_len, evp_ctxt, evp_len))
            goto end;

        /* ---------- Decrypt the ciphertext using BIO_f_cipher ---------- */
        src2 = BIO_new_mem_buf(bio_ctxt, bio_len);
        if (!TEST_ptr(src2))
            goto end;
        dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec))
            goto end;
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                      key, iv, 0)))   /* 0 = decrypt */
            goto end;
        BIO_push(dec, src2);

        dec_len = 0;
        while ((n = BIO_read(dec, dec_plain + dec_len,
                             (int)sizeof(dec_plain) - dec_len)) > 0) {
            dec_len += n;
            if (dec_len == (int)sizeof(dec_plain))
                break;
        }
        if (!TEST_int_eq(BIO_should_retry(dec), 0))
            goto end;
        if (!TEST_int_eq(dec_len, plen))
            goto end;
        if (!TEST_mem_eq(dec_plain, dec_len, plaintext, plen))
            goto end;

        ret = 1; /* all checks passed */

    end:
        EVP_CIPHER_CTX_free(ctx);
        BIO_free_all(enc);
        BIO_free_all(dec);
        /* src and src2 are freed by BIO_free_all above (they are linked) */
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
