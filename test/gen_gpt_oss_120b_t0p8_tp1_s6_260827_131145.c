/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp1_s6_260827_131145.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test AES‑256‑CBC encryption followed by decryption using the BIO
     * cipher filter. The decrypted output must match the original plaintext. */
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
    };
    const unsigned char plaintext[] = "OpenSSL BIO cipher round‑trip test data";
    const size_t plen = sizeof(plaintext) - 1; /* exclude terminating NUL */

    BIO *enc = NULL, *mem_out = NULL;
    BIO *dec = NULL, *mem_in = NULL;
    char *cipherdata = NULL;
    long cipherlen = 0;
    unsigned char outbuf[128];
    int outlen = 0;

    /* ---------- Encryption side ---------- */
    if (!TEST_ptr(enc = BIO_new(BIO_f_cipher())))
        return 0;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* 1 = encrypt */
        goto err;
    if (!TEST_ptr(mem_out = BIO_new(BIO_s_mem())))
        goto err;
    BIO_push(enc, mem_out);

    if (!TEST_int_eq(BIO_write(enc,
                               (const char *)plaintext,
                               (int)plen), (int)plen))
        goto err;
    if (!TEST_int_eq(BIO_flush(enc), 1))
        goto err;

    cipherlen = BIO_get_mem_data(mem_out, &cipherdata);
    if (!TEST_int_gt(cipherlen, 0))
        goto err;

    /* ---------- Decryption side ---------- */
    if (!TEST_ptr(mem_in = BIO_new_mem_buf(cipherdata, (int)cipherlen)))
        goto err;
    if (!TEST_ptr(dec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* 0 = decrypt */
        goto err;
    BIO_push(dec, mem_in);

    outlen = BIO_read(dec, outbuf, (int)plen);
    if (!TEST_int_eq(outlen, (int)plen))
        goto err;
    if (!TEST_mem_eq(outbuf, plen, plaintext, plen))
        goto err;

    /* Clean up and report success */
    BIO_free_all(enc);
    BIO_free_all(dec);
    return 1;

err:
    BIO_free_all(enc);
    BIO_free_all(dec);
    return 0;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
