/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s5_260827_131108.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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

        /* Test vectors from NIST SP 800-38A */
        static const unsigned char key[32] = {
            0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
            0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
            0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
        };
        static const unsigned char iv[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };
        static const unsigned char plaintext[64] = {
            0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
            0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
            0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
            0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
            0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,
            0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
            0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,
            0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10
        };
        static const unsigned char expected_ciphertext[64] = {
            0xf5,0x8c,0x4c,0x04,0xd6,0xe5,0xf1,0xba,
            0x77,0x9e,0xb5,0x21,0x2a,0xd5,0x2a,0x1e,
            0x64,0x4b,0x1f,0xd3,0xaf,0x4a,0x9c,0x8a,
            0x0c,0x5c,0x70,0x0a,0x9b,0x2c,0xdd,0x5b,
            0x7b,0x3b,0x2e,0x3e,0x57,0x1c,0xc4,0x1b,
            0x6b,0x04,0x8b,0x0c,0x73,0x8a,0xd6,0x45,
            0xd5,0x2d,0x49,0x2c,0x4c,0xb7,0x39,0xc3,
            0xc0,0x2b,0x9e,0xc5,0x9b,0x69,0x5a,0x1c
        };

        /* -------------------- Encryption -------------------- */
        BIO *mem_enc = BIO_new(BIO_s_mem());
        BIO *benc = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_enc) || !TEST_ptr(benc))
            return 0;

        if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                     key, iv, 1)))
            ok = 0;

        BIO_push(benc, mem_enc);

        if (ok && !TEST_int_eq(BIO_write(benc, plaintext,
                                         sizeof(plaintext)),
                               (int)sizeof(plaintext)))
            ok = 0;

        if (ok && !TEST_int_eq(BIO_flush(benc), 1))
            ok = 0;

        /* Retrieve ciphertext from memory BIO */
        char *enc_out = NULL;
        long enc_len = BIO_get_mem_data(mem_enc, &enc_out);

        if (ok && !TEST_int_eq(enc_len, (long)sizeof(expected_ciphertext)))
            ok = 0;
        if (ok && !TEST_mem_eq(enc_out, enc_len,
                               expected_ciphertext, sizeof(expected_ciphertext)))
            ok = 0;

        BIO_free_all(benc); /* also frees mem_enc */

        /* -------------------- Decryption -------------------- */
        BIO *mem_dec = BIO_new_mem_buf(expected_ciphertext,
                                      sizeof(expected_ciphertext));
        BIO *bdec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_dec) || !TEST_ptr(bdec))
            return 0;

        if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                     key, iv, 0)))
            ok = 0;

        BIO_push(bdec, mem_dec);

        unsigned char dec_out[sizeof(plaintext)];
        int dec_total = 0;
        while (dec_total < (int)sizeof(plaintext)) {
            int r = BIO_read(bdec, dec_out + dec_total,
                             sizeof(plaintext) - dec_total);
            if (r <= 0) {
                if (!BIO_should_retry(bdec))
                    break;
            } else {
                dec_total += r;
            }
        }

        if (ok && !TEST_int_eq(dec_total, (int)sizeof(plaintext)))
            ok = 0;
        if (ok && !TEST_mem_eq(dec_out, dec_total,
                               plaintext, sizeof(plaintext)))
            ok = 0;

        BIO_free_all(bdec); /* also frees mem_dec */

        return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
