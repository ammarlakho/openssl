/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p6_tp1_s6_260827_130122.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Test BIO_f_cipher round‑trip using AES‑256‑CBC.
         * Encrypt a known plaintext, then decrypt the ciphertext and
         * verify the output matches the original data. */
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
        const unsigned char plaintext[] = "OpenSSL BIO cipher round‑trip test vector";
        const int plaintext_len = (int)sizeof(plaintext) - 1; /* exclude NUL */

        BIO *mem = NULL, *enc = NULL;
        BUF_MEM *bptr = NULL;
        unsigned char *ciphertext = NULL;
        int ciphertext_len = 0;
        int ok = 0; /* final result */

        /* ---------- Encryption ---------- */
        mem = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem))
            goto end;
        enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(enc))
            goto end;
        if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                    key, iv, 1)))   /* encrypt */
            goto end;
        enc = BIO_push(enc, mem);               /* enc is now the top BIO */

        if (!TEST_int_eq(BIO_write(enc,
                                   (const char *)plaintext,
                                   plaintext_len), plaintext_len))
            goto end;
        if (!TEST_true(BIO_flush(enc)))        /* ensure final block is written */
            goto end;

        /* Obtain ciphertext from the memory BIO */
        BIO_get_mem_ptr(mem, &bptr);
        if (!TEST_ptr(bptr))
            goto end;
        ciphertext_len = bptr->length;
        if (!TEST_int_gt(ciphertext_len, 0))
            goto end;
        ciphertext = OPENSSL_malloc(ciphertext_len);
        if (!TEST_ptr(ciphertext))
            goto end;
        memcpy(ciphertext, bptr->data, ciphertext_len);

        /* Free the encryption chain – the copied ciphertext remains valid */
        BIO_free_all(enc);
        enc = NULL;
        mem = NULL;

        /* ---------- Decryption ---------- */
        BIO *src = BIO_new_mem_buf(ciphertext, ciphertext_len);
        BIO *dec = NULL;
        if (!TEST_ptr(src))
            goto end;
        dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(dec))
            goto end;
        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                    key, iv, 0)))   /* decrypt */
            goto end;
        dec = BIO_push(dec, src);               /* dec is now the top BIO */

        unsigned char outbuf[1024];
        int outlen = 0, r;

        while ((r = BIO_read(dec, outbuf + outlen,
                            (int)sizeof(outbuf) - outlen)) > 0) {
            outlen += r;
            if (outlen == (int)sizeof(outbuf))
                break;   /* should never happen for this test */
        }

        /* Verify that the decrypted data matches the original plaintext */
        ok = TEST_int_eq(outlen, plaintext_len) &&
             TEST_mem_eq(outbuf, outlen, plaintext, plaintext_len);

    end:
        if (enc) BIO_free_all(enc);
        if (dec) BIO_free_all(dec);
        if (ciphertext) OPENSSL_free(ciphertext);
        return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
