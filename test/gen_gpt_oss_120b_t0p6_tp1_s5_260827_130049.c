/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p6_tp1_s5_260827_130049.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
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
            "OpenSSL BIO cipher round‑trip test data.";
        const int plen = (int)(sizeof(plaintext) - 1); /* exclude NUL */

        BIO *mem = NULL, *enc = NULL, *dec = NULL, *mem_in = NULL;
        char *cdata = NULL;
        long clen = 0;
        unsigned char outbuf[256];
        int outlen = 0;
        int ret = 0;

        /* ----- encryption side ----- */
        if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
            goto end;
        if (!TEST_ptr(enc = BIO_new(BIO_f_cipher())))
            goto end;
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                    key, iv, 1))) /* encrypt */
            goto end;
        BIO_push(enc, mem);

        if (!TEST_int_eq(BIO_write(enc,
                                  (const char *)plaintext, plen), plen))
            goto end;
        if (!TEST_true(BIO_flush(enc)))
            goto end;

        /* obtain the ciphertext from the memory BIO */
        clen = BIO_get_mem_data(mem, &cdata);
        if (!TEST_int_gt((int)clen, 0))
            goto end;

        /* ----- decryption side ----- */
        if (!TEST_ptr(mem_in = BIO_new_mem_buf(cdata, (int)clen)))
            goto end;
        if (!TEST_ptr(dec = BIO_new(BIO_f_cipher())))
            goto end;
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                    key, iv, 0))) /* decrypt */
            goto end;
        BIO_push(dec, mem_in);

        outlen = BIO_read(dec, outbuf, sizeof(outbuf));
        if (!TEST_int_gt(outlen, 0))
            goto end;
        if (!TEST_int_eq(outlen, plen))
            goto end;
        if (!TEST_mem_eq(outbuf, outlen, plaintext, plen))
            goto end;

        ret = 1;               /* all checks passed */

    end:
        BIO_free_all(enc);     /* also frees mem */
        BIO_free_all(dec);     /* also frees mem_in */
        return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
