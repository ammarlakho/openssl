/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp1_s4_260827_123934.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
static int test_bio_enc_generated(void)
{
    /* Test AES‑256‑CBC encryption/decryption using the BIO_f_cipher filter. */
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

    /* ---------- Encryption ---------- */
    BIO *mem_enc = BIO_new(BIO_s_mem());
    BIO *enc = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_enc) || !TEST_ptr(enc))
        return 0;

    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* encrypt */
        return 0;

    enc = BIO_push(enc, mem_enc);               /* enc -> mem_enc */

    if (!TEST_int_eq(BIO_write(enc, plaintext, pt_len), pt_len))
        return 0;

    if (!TEST_int_eq(BIO_flush(enc), 1))
        return 0;

    /* Retrieve ciphertext from the memory BIO */
    char *cipherdata = NULL;
    long cipherlen = BIO_get_mem_data(mem_enc, &cipherdata);
    if (!TEST_int_gt(cipherlen, 0))
        return 0;

    /* ---------- Decryption ---------- */
    BIO *mem_dec = BIO_new_mem_buf(cipherdata, (int)cipherlen);
    BIO *dec = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_dec) || !TEST_ptr(dec))
        return 0;

    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* decrypt */
        return 0;

    dec = BIO_push(dec, mem_dec);               /* dec -> mem_dec */

    unsigned char outbuf[256];
    int outlen = 0, r;

    while ((r = BIO_read(dec, outbuf + outlen,
                        (int)sizeof(outbuf) - outlen)) > 0) {
        outlen += r;
        if (outlen == (int)sizeof(outbuf))
            break;
    }

    if (!TEST_int_eq(outlen, pt_len))
        return 0;

    if (!TEST_mem_eq(outbuf, outlen, plaintext, pt_len))
        return 0;

    /* Clean up */
    BIO_free_all(enc);   /* also frees mem_enc */
    BIO_free_all(dec);   /* also frees mem_dec */

    return 1;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
