/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p4_tp1_s7_260827_125334.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test AES‑256‑CBC encryption/decryption using BIO_f_cipher.
         * The plaintext is encrypted through a cipher BIO that writes into a
         * memory BIO, then the resulting ciphertext is read back through a
         * second cipher BIO (decrypt mode) and compared with the original.
         */
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
            "OpenSSL BIO cipher test vector data";
        const size_t pt_len = sizeof(plaintext) - 1; /* omit trailing NUL */

        /* ---------- Encryption ---------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *bio_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_enc) || !TEST_ptr(bio_enc))
            return 0;

        if (!TEST_true(BIO_set_cipher(bio_enc, EVP_aes_256_cbc(),
                                      key, iv, 1))) {
            BIO_free_all(bio_enc);
            return 0;
        }

        /* Chain: bio_enc -> mem_enc */
        BIO_push(bio_enc, mem_enc);

        if (!TEST_int_eq(BIO_write(bio_enc, plaintext, (int)pt_len), (int)pt_len))
            goto enc_err;
        if (!TEST_int_eq(BIO_flush(bio_enc), 1))
            goto enc_err;

        /* Extract ciphertext from the memory BIO */
        BUF_MEM *bptr = NULL;
        if (!TEST_true(BIO_get_mem_ptr(mem_enc, &bptr)))
            goto enc_err;
        if (!TEST_ptr(bptr))
            goto enc_err;

        unsigned char *ciphertext = OPENSSL_malloc(bptr->length);
        if (!TEST_ptr(ciphertext))
            goto enc_err;
        memcpy(ciphertext, bptr->data, bptr->length);
        size_t ct_len = bptr->length;

        /* Clean up encryption chain */
        BIO_free_all(bio_enc);
        bio_enc = NULL;
        mem_enc = NULL;

        /* ---------- Decryption ---------- */
        BIO *mem_dec = BIO_new_mem_buf(ciphertext, (int)ct_len);
        BIO *bio_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(mem_dec) || !TEST_ptr(bio_dec))
            goto dec_err;

        if (!TEST_true(BIO_set_cipher(bio_dec, EVP_aes_256_cbc(),
                                      key, iv, 0))) {
            BIO_free_all(bio_dec);
            goto dec_err;
        }

        /* Chain: bio_dec -> mem_dec */
        BIO_push(bio_dec, mem_dec);

        unsigned char outbuf[256];
        int outlen = BIO_read(bio_dec, outbuf, sizeof(outbuf));
        if (!TEST_int_gt(outlen, 0))
            goto dec_err;
        if (!TEST_int_eq(outlen, (int)pt_len))
            goto dec_err;
        if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len))
            goto dec_err;

        /* Verify cipher status (should be OK) */
        long status = BIO_ctrl(bio_dec, BIO_C_GET_CIPHER_STATUS, 0, NULL);
        if (!TEST_long_eq(status, 1))
            goto dec_err;

        /* Clean up decryption chain */
        BIO_free_all(bio_dec);
        OPENSSL_free(ciphertext);
        return 1;

    enc_err:
        BIO_free_all(bio_enc);
        OPENSSL_free(ciphertext);
        return 0;
    dec_err:
        BIO_free_all(bio_dec);
        OPENSSL_free(ciphertext);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
