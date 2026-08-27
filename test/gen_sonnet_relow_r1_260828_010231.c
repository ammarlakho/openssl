/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_relow_r1_260828_010231.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
};
static const unsigned char plaintext[] =
    "The quick brown fox jumps over the lazy dog. "
    "Pack my box with five dozen liquor jugs.";
unsigned char ciphertext[256];
unsigned char decrypted[256];
BIO *benc = NULL, *bmem = NULL, *bsrc = NULL;
int outlen, totallen, ret = 0;
int n;

/* --- Encrypt path --- */
if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
    goto end;
if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
    goto end;
if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1 /* encrypt */)))
    goto end;

if (!TEST_ptr(BIO_push(benc, bmem)))
    goto end;

if (!TEST_int_eq(BIO_write(benc, plaintext, (int)sizeof(plaintext)),
                  (int)sizeof(plaintext)))
    goto end;

if (!TEST_int_gt(BIO_flush(benc), 0))
    goto end;

n = BIO_read(bmem, ciphertext, sizeof(ciphertext));
if (!TEST_int_gt(n, 0))
    goto end;
totallen = n;

/* Ciphertext should differ from plaintext */
if (!TEST_mem_ne(ciphertext, totallen, plaintext, sizeof(plaintext)))
    goto end;

BIO_free(benc);
benc = NULL;
BIO_free(bmem);
bmem = NULL;

/* --- Decrypt path --- */
if (!TEST_ptr(bsrc = BIO_new_mem_buf(ciphertext, totallen)))
    goto end;
if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
    goto end;
if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 0 /* decrypt */)))
    goto end;
if (!TEST_ptr(BIO_push(benc, bsrc)))
    goto end;

outlen = BIO_read(benc, decrypted, sizeof(decrypted));
if (!TEST_int_eq(outlen, (int)sizeof(plaintext)))
    goto end;

if (!TEST_mem_eq(decrypted, outlen, plaintext, sizeof(plaintext)))
    goto end;

if (!TEST_true(BIO_get_cipher_status(benc)))
    goto end;

ret = 1;

end:
BIO_free(benc);
BIO_free(bmem);
BIO_free(bsrc);
return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
