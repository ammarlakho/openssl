/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_relow_r5_260828_010320.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
static const unsigned char key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static const unsigned char iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const unsigned char plaintext[] =
    "The quick brown fox jumps over the lazy dog. "
    "AES-256 CBC round trip test via BIO_f_cipher().";

BIO *benc = NULL, *bmem = NULL;
unsigned char *encoded = NULL, decoded[512];
long enc_len = 0;
int dec_total = 0, n;
int ok = 0;

bmem = BIO_new(BIO_s_mem());
if (!TEST_ptr(bmem))
    goto err;

benc = BIO_new(BIO_f_cipher());
if (!TEST_ptr(benc))
    goto err;

if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
    goto err;

if (!TEST_ptr(BIO_push(benc, bmem)))
    goto err;

if (!TEST_int_eq(BIO_write(benc, plaintext, (int)strlen((const char *)plaintext)),
                  (int)strlen((const char *)plaintext)))
    goto err;

if (!TEST_int_gt(BIO_flush(benc), 0))
    goto err;

enc_len = BIO_get_mem_data(bmem, &encoded);
if (!TEST_int_gt((int)enc_len, 0))
    goto err;

/* Encrypted length must be padded to a multiple of the block size */
if (!TEST_int_eq((int)(enc_len % 16), 0))
    goto err;

/* Ciphertext should differ from plaintext */
if (!TEST_mem_ne(encoded, (size_t)enc_len, plaintext, strlen((const char *)plaintext)))
    goto err;

BIO_free(benc);
benc = NULL;

/* Now decrypt into a fresh mem BIO chain */
bmem = BIO_new_mem_buf(encoded, (int)enc_len);
if (!TEST_ptr(bmem))
    goto err;

benc = BIO_new(BIO_f_cipher());
if (!TEST_ptr(benc))
    goto err;

if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 0)))
    goto err;

if (!TEST_ptr(BIO_push(benc, bmem)))
    goto err;

memset(decoded, 0, sizeof(decoded));
n = BIO_read(benc, decoded, sizeof(decoded));
if (!TEST_int_gt(n, 0))
    goto err;
dec_total = n;

if (!TEST_int_eq(BIO_get_cipher_status(benc), 1))
    goto err;

if (!TEST_mem_eq(decoded, dec_total, plaintext, strlen((const char *)plaintext)))
    goto err;

ok = 1;

err:
BIO_free(benc);
BIO_free(bmem);
return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
