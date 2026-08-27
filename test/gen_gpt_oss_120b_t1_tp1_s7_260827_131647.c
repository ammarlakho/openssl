/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s7_260827_131647.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test AES‑256‑CBC encryption/decryption using the cipher BIO.
         * The data is encrypted with a cipher BIO pushed onto a memory BIO,
         * then the ciphertext is read back and fed into a second cipher BIO
         * (decryption mode) also stacked on a memory BIO.  The final output
         * must match the original plaintext. */
        const unsigned char key[32] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
        };
        const unsigned char iv[16] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        const int pt_len = (int)sizeof(plaintext) - 1; /* exclude NUL */
        int ret = 0;               /* overall result */
        int i;
        BIO *mem_enc = NULL, *cipher_enc = NULL;
        BIO *mem_dec = NULL, *cipher_dec = NULL;
        BUF_MEM *bptr = NULL;
        unsigned char *dec_buf = NULL;
        int dec_len = 0;

        /* ---------- Encryption side ---------- */
        mem_enc = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_enc))
            goto err;

        cipher_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_enc))
            goto err;

        /* Set up encryption (e = 1) */
        if (!TEST_true(BIO_set_cipher(cipher_enc, EVP_aes_256_cbc(),
                                   key, iv, 1)))
            goto err;

        /* Stack: cipher_enc -> mem_enc */
        cipher_enc = BIO_push(cipher_enc, mem_enc);

        i = BIO_write(cipher_enc, plaintext, pt_len);
        if (!TEST_int_eq(i, pt_len))
            goto err;

        if (!TEST_true(BIO_flush(cipher_enc)))
            goto err;

        /* Retrieve the ciphertext from the memory BIO */
        if (!TEST_true(BIO_get_mem_ptr(mem_enc, &bptr)))
            goto err;

        /* ---------- Decryption side ---------- */
        mem_dec = BIO_new_mem_buf(bptr->data, bptr->length);
        if (!TEST_ptr(mem_dec))
            goto err;

        cipher_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_dec))
            goto err;

        /* Set up decryption (e = 0) */
        if (!TEST_true(BIO_set_cipher(cipher_dec, EVP_aes_256_cbc(),
                                   key, iv, 0)))
            goto err;

        /* Stack: cipher_dec -> mem_dec */
        cipher_dec = BIO_push(cipher_dec, mem_dec);

        /* Allocate a buffer large enough for the plaintext (including possible padding) */
        dec_buf = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH);
        if (!TEST_ptr(dec_buf))
            goto err;

        dec_len = BIO_read(cipher_dec, dec_buf, pt_len + EVP_MAX_BLOCK_LENGTH);
        if (!TEST_int_gt(dec_len, 0))
            goto err;

        if (!TEST_int_eq(dec_len, pt_len))
            goto err;

        if (!TEST_mem_eq(dec_buf, dec_len, plaintext, pt_len))
            goto err;

        /* All checks passed */
        ret = 1;

    err:
        /* Clean‑up */
        if (dec_buf != NULL)
            OPENSSL_free(dec_buf);
        if (cipher_dec != NULL)
            BIO_free_all(cipher_dec);
        else if (mem_dec != NULL)
            BIO_free_all(mem_dec);
        if (cipher_enc != NULL)
            BIO_free_all(cipher_enc);
        else if (mem_enc != NULL)
            BIO_free_all(mem_enc);
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
