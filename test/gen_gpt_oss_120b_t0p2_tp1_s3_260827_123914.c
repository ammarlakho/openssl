/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp1_s3_260827_123914.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test BIO_f_cipher AES‑256‑CBC encrypt‑then‑decrypt round‑trip */
        const unsigned char key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        const unsigned char iv[16] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
        };
        const unsigned char plaintext[] =
            "The quick brown fox jumps over the lazy dog";
        const int pt_len = (int)strlen((const char *)plaintext);

        /* ---------- Encryption ---------- */
        BIO *out_mem = BIO_new(BIO_s_mem());
        BIO *enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(out_mem) || !TEST_ptr(enc))
            return 0;
        BIO_push(enc, out_mem);

        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                    key, iv, 1))) {
            BIO_free_all(enc);
            return 0;
        }

        if (!TEST_int_eq(BIO_write(enc, plaintext, pt_len), pt_len))
            goto err;
        if (!TEST_true(BIO_flush(enc)))
            goto err;

        /* Obtain ciphertext from the memory BIO */
        char *cdata = NULL;
        long c_len = BIO_get_mem_data(out_mem, &cdata);
        if (!TEST_int_gt(c_len, 0))
            goto err;

        /* ---------- Decryption ---------- */
        BIO *in_mem = BIO_new_mem_buf(cdata, (int)c_len);
        BIO *dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(in_mem) || !TEST_ptr(dec))
            goto err;
        BIO_push(dec, in_mem);

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                    key, iv, 0))) {
            BIO_free_all(dec);
            goto err;
        }

        unsigned char outbuf[256];
        int total = 0, r;
        while (total < (int)sizeof(outbuf)) {
            r = BIO_read(dec, outbuf + total,
                         (int)sizeof(outbuf) - total);
            if (r > 0) {
                total += r;
                continue;
            }
            if (r == 0)
                break;
            if (!BIO_should_retry(dec))
                break;
        }

        if (!TEST_int_eq(total, pt_len))
            goto err;
        if (!TEST_mem_eq(outbuf, pt_len, plaintext, pt_len))
            goto err;

        /* Clean up */
        BIO_free_all(enc);
        BIO_free_all(dec);
        return 1;

    err:
        BIO_free_all(enc);
        BIO_free_all(dec);
        return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
