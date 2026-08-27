/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_relow_r4_260828_010309.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    "This is a test message for AES-256 CBC BIO round-trip testing.";

BIO *benc = NULL, *bmem = NULL;
unsigned char *encbuf = NULL;
long enclen = 0;
unsigned char decbuf[512];
int declen = 0, ret = 0, n;
int ok = 0;

/* Encrypt path: memory BIO wrapped by cipher BIO */
bmem = BIO_new(BIO_s_mem());
if (!TEST_ptr(bmem))
    goto err;
benc = BIO_new(BIO_f_cipher());
if (!TEST_ptr(benc))
    goto err;
if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
    goto err;

BIO_push(benc, bmem);
bmem = NULL; /* now owned by chain */

if (!TEST_int_eq(BIO_write(benc, plaintext, (int)sizeof(plaintext)),
                  (int)sizeof(plaintext)))
    goto err;
if (!TEST_int_ge(BIO_flush(benc), 0))
    goto err;

bmem = BIO_next(benc);
enclen = BIO_get_mem_data(bmem, &encbuf);
if (!TEST_int_gt((int)enclen, 0))
    goto err;

BIO_free(benc);
benc = NULL;

/* Sanity: ciphertext must differ from plaintext */
if (!TEST_mem_ne(encbuf, (size_t)enclen, plaintext, sizeof(plaintext)))
    goto err;

/* Decrypt path */
bmem = BIO_new_mem_buf(encbuf, (int)enclen);
if (!TEST_ptr(bmem))
    goto err;
benc = BIO_new(BIO_f_cipher());
if (!TEST_ptr(benc))
    goto err;
if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 0)))
    goto err;

BIO_push(benc, bmem);
bmem = NULL;

declen = 0;
while ((n = BIO_read(benc, decbuf + declen,
                      (int)(sizeof(decbuf) - declen))) > 0) {
    declen += n;
    if (declen >= (int)sizeof(decbuf))
        break;
}

if (!TEST_int_eq(declen, (int)sizeof(plaintext)))
    goto err;
if (!TEST_mem_eq(decbuf, declen, plaintext, sizeof(plaintext)))
    goto err;

ok = 1;

err:
BIO_free(benc);
BIO_free(bmem);
ret = ok;
return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
