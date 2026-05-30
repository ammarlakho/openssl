/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include "testutil.h"

#define ENCRYPT 1
#define DECRYPT 0

static const char PLAINTEXT[] = "Hello, World!";

/* Same sizes as bio_enc_test.c; AES-256-CBC uses the first 16 IV bytes. */
static const unsigned char KEY[] = {
    0x51, 0x50, 0xd1, 0x77, 0x2f, 0x50, 0x83, 0x4a,
    0x50, 0x3e, 0x06, 0x9a, 0x97, 0x3f, 0xbd, 0x7c,
    0xe6, 0x1c, 0x43, 0x2b, 0x72, 0x0b, 0x19, 0xd1,
    0x8e, 0xc8, 0xd8, 0x4b, 0xdc, 0x63, 0x15, 0x1b
};

static const unsigned char IV[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

static int test_bio_enc_aes256_cbc_roundtrip(void)
{
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    BIO *cbio = NULL, *mem = NULL;
    unsigned char ct_buf[256];
    unsigned char pt_buf[256];
    int pt_len = (int)strlen(PLAINTEXT);
    int ct_len, dec_len;

    if (!TEST_ptr(cbio = BIO_new(BIO_f_cipher())))
        return 0;
    if (!TEST_true(BIO_set_cipher(cbio, cipher, KEY, IV, ENCRYPT)))
        goto err;
    if (!TEST_ptr(mem = BIO_new_mem_buf(PLAINTEXT, pt_len)))
        goto err;
    if (!TEST_ptr(BIO_push(cbio, mem)))
        goto err;
    mem = NULL;

    ct_len = BIO_read(cbio, ct_buf, sizeof(ct_buf));
    BIO_free_all(cbio);
    cbio = NULL;

    if (!TEST_int_gt(ct_len, pt_len))
        return 0;

    if (!TEST_ptr(cbio = BIO_new(BIO_f_cipher())))
        return 0;
    if (!TEST_true(BIO_set_cipher(cbio, cipher, KEY, IV, DECRYPT)))
        goto err;
    if (!TEST_ptr(mem = BIO_new_mem_buf(ct_buf, ct_len)))
        goto err;
    if (!TEST_ptr(BIO_push(cbio, mem)))
        goto err;
    mem = NULL;

    dec_len = BIO_read(cbio, pt_buf, sizeof(pt_buf));
    BIO_free_all(cbio);
    cbio = NULL;

    if (!TEST_int_eq(dec_len, pt_len))
        return 0;
    return TEST_mem_eq(PLAINTEXT, (size_t)pt_len, pt_buf, (size_t)dec_len);

err:
    BIO_free_all(cbio);
    return 0;
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_aes256_cbc_roundtrip);
    return 1;
}
