/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p5_tp1_s6_260827_125716.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        const char *plaintext = "Test vector for BIO cipher round‑trip.";
        size_t ptlen = strlen(plaintext);
        BIO *bmem = NULL, *bcipher = NULL;
        BIO *src = NULL, *bdec = NULL;
        unsigned char *ciphertext = NULL;
        long c_len = 0;
        unsigned char outbuf[256];
        int outlen = 0, r, total = 0;
        int ok = 0; /* return value */

        /* ---------- Encryption ---------- */
        bmem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(bmem))
            goto end;
        bcipher = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bcipher))
            goto end;
        if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(),
                                      key, iv, 1)))
            goto end;
        BIO_push(bcipher, bmem);

        if (!TEST_int_ge(BIO_write(bcipher, plaintext, (int)ptlen), 0))
            goto end;
        if (!TEST_int_ge(BIO_flush(bcipher), 0))
            goto end;

        /* Retrieve ciphertext from the memory BIO */
        c_len = BIO_get_mem_data(bmem, (char **)&ciphertext);
        if (!TEST_int_gt(c_len, 0))
            goto end;

        /* Copy the ciphertext out before freeing the BIO chain */
        ciphertext = OPENSSL_malloc(c_len);
        if (!TEST_ptr(ciphertext))
            goto end;
        memcpy(ciphertext, BIO_get_mem_data(bmem, (char **)&ciphertext), c_len);

        /* Free the encryption BIO chain (also frees bmem) */
        BIO_free_all(bcipher);
        bcipher = NULL;
        bmem = NULL;

        /* ---------- Decryption ---------- */
        src = BIO_new_mem_buf(ciphertext, (int)c_len);
        if (!TEST_ptr(src))
            goto end;
        bdec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(bdec))
            goto end;
        if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                      key, iv, 0)))
            goto end;
        BIO_push(bdec, src);

        /* Read all decrypted data */
        total = 0;
        while ((r = BIO_read(bdec, outbuf + total,
                             sizeof(outbuf) - total)) > 0) {
            total += r;
            if (total == sizeof(outbuf))
                break; /* buffer full – should not happen for this test */
        }
        if (!TEST_int_ge(r, 0))          /* error on read */
            goto end;
        if (!TEST_int_ge(BIO_flush(bdec), 0))
            goto end;

        /* Compare the decrypted output with the original plaintext */
        if (!TEST_mem_eq(outbuf, total, plaintext, ptlen))
            goto end;

        ok = 1;   /* success */

    end:
        BIO_free_all(bcipher);
        BIO_free_all(bmem);
        BIO_free_all(bdec);
        BIO_free_all(src);
        OPENSSL_free(ciphertext);
        return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
