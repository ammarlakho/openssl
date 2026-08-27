/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp0p95_fp0_s2_260827_002846.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test that BIO_f_cipher correctly encrypts and decrypts data using
         * AES‑256‑CBC.  The test encrypts a known plaintext, then decrypts the
         * resulting ciphertext and checks that the original plaintext is
         * recovered and that the cipher status reports success. */
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
        const char plaintext[] =
            "OpenSSL test vector for BIO_f_cipher";
        const int pt_len = (int)strlen(plaintext);
        int ok = 1;
        BIO *mem = NULL, *enc = NULL, *dec = NULL, *in = NULL;
        char *cdata = NULL;
        long c_len = 0;
        unsigned char outbuf[1024];
        int out_len = 0, r;

        /* ----- Encryption ------------------------------------------------- */
        mem = BIO_new(BIO_s_mem());
        ok &= TEST_ptr(mem);

        enc = BIO_new(BIO_f_cipher());
        ok &= TEST_ptr(enc);
        ok &= TEST_true(BIO_set_cipher(enc,
                         EVP_aes_256_cbc(),
                         key, iv, 1));           /* 1 = encrypt */

        /* Chain: enc -> mem */
        enc = BIO_push(enc, mem);

        r = BIO_write(enc, plaintext, pt_len);
        ok &= TEST_int_eq(r, pt_len);

        ok &= TEST_true(BIO_flush(enc));

        /* Retrieve ciphertext from the memory BIO */
        c_len = BIO_get_mem_data(mem, &cdata);
        ok &= TEST_true(c_len > 0);
        ok &= TEST_ptr(cdata);

        /* ----- Decryption ------------------------------------------------- */
        in = BIO_new_mem_buf(cdata, (int)c_len);
        ok &= TEST_ptr(in);

        dec = BIO_new(BIO_f_cipher());
        ok &= TEST_ptr(dec);
        ok &= TEST_true(BIO_set_cipher(dec,
                         EVP_aes_256_cbc(),
                         key, iv, 0));           /* 0 = decrypt */

        /* Chain: dec -> in */
        dec = BIO_push(dec, in);

        out_len = 0;
        while ((r = BIO_read(dec, outbuf + out_len,
                            (int)sizeof(outbuf) - out_len)) > 0) {
            out_len += r;
        }
        ok &= TEST_true(!BIO_should_retry(dec));

        ok &= TEST_int_eq(out_len, pt_len);
        ok &= TEST_mem_eq(outbuf, out_len, plaintext, pt_len);

        /* Verify cipher status reports success */
        {
            long status = BIO_ctrl(dec, BIO_C_GET_CIPHER_STATUS, 0, NULL);
            ok &= TEST_true(status == 1);
        }

        /* Clean up */
        BIO_free_all(dec);   /* frees the whole chain (dec + in) */
        BIO_free_all(enc);   /* frees the whole chain (enc + mem) */

        return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
