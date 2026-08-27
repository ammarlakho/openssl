/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_relow_r3_260828_010257.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    "Pack my box with five dozen liquor jugs. "
    "0123456789ABCDEF";
int plen = (int)strlen((const char *)plaintext);
BIO *benc = NULL, *bmem = NULL;
unsigned char cipherbuf[4096];
unsigned char decbuf[4096];
int clen = 0, tot = 0, r, dlen = 0;
BIO *bdec = NULL, *bmem2 = NULL;

/* Encrypt: BIO_f_cipher() chained to a memory BIO */
if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
    goto err;
if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
    goto err;
if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
    goto err;
BIO_push(benc, bmem);

if (!TEST_int_eq(BIO_write(benc, plaintext, plen), plen))
    goto err;
if (!TEST_int_ge(BIO_flush(benc), 0))
    goto err;
if (!TEST_true(BIO_get_cipher_status(benc)))
    goto err;

clen = BIO_read(bmem, cipherbuf, sizeof(cipherbuf));
if (!TEST_int_gt(clen, 0))
    goto err;
/* CBC output should be padded to a multiple of block size */
if (!TEST_int_eq(clen % EVP_CIPHER_get_block_size(EVP_aes_256_cbc()), 0))
    goto err;

BIO_free(benc);
benc = NULL;
bmem = NULL; /* freed by BIO_free(benc) via push chain */

/* Decrypt: feed ciphertext through a mem BIO -> BIO_f_cipher() */
if (!TEST_ptr(bmem2 = BIO_new(BIO_s_mem())))
    goto err;
if (!TEST_int_eq(BIO_write(bmem2, cipherbuf, clen), clen))
    goto err;
if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
    goto err;
if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
    goto err;
BIO_push(bdec, bmem2);

tot = 0;
while ((r = BIO_read(bdec, decbuf + tot, sizeof(decbuf) - tot)) > 0)
    tot += r;
dlen = tot;

if (!TEST_true(BIO_get_cipher_status(bdec)))
    goto err;
if (!TEST_int_eq(dlen, plen))
    goto err;
if (!TEST_mem_eq(decbuf, dlen, plaintext, plen))
    goto err;

BIO_free(bdec);
return 1;

err:
BIO_free(benc);
BIO_free(bdec);
return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
