/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s7_260827_154143.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 0;
    BIO *bmem = NULL, *benc = NULL, *bdec = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                              0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                              0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    
    /* 
     * Use a data size larger than ENC_BLOCK_SIZE (4096) to exercise 
     * the internal buffering logic in bio_enc.c 
     */
    int plain_len = 8192 + 123; 
    unsigned char *plain = OPENSSL_malloc(plain_len);
    unsigned char *out = OPENSSL_malloc(plain_len + EVP_MAX_BLOCK_LENGTH);
    int written = 0, read_len = 0;

    if (!TEST_ptr(plain) || !TEST_ptr(out))
        goto err;

    memset(plain, 'A', plain_len);
    memset(out, 0, plain_len + EVP_MAX_BLOCK_LENGTH);

    /* 1. Setup Encryption Chain: benc (filter) -> bmem (sink) */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto err;

    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;

    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 1)))
        goto err;

    /* Write plaintext to the cipher BIO */
    written = BIO_write(benc, plain, plain_len);
    if (!TEST_true(written == plain_len))
        goto err;

    /* Flush to ensure padding is written to bmem */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* 
     * Prepare for decryption by disconnecting the encryption filter
     * and resetting the memory BIO read pointer.
     */
    BIO_set_close(benc, 0); 
    BIO_free(benc); 
    if (!TEST_true(BIO_reset(bmem)))
        goto err;

    /* 2. Setup Decryption Chain: bdec (filter) -> bmem (source) */
    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;

    if (!TEST_true(BIO_push(bdec, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, cipher, key, iv, 0)))
        goto err;

    /* Read decrypted data from the cipher BIO */
    while ((written = BIO_read(bdec, (char *)out + read_len, plain_len - read_len)) > 0) {
        read_len += written;
    }

    if (!TEST_true(read_len == plain_len))
        goto err;

    if (!TEST_mem_eq(plain, plain_len, out, read_len))
        goto err;

    ok = 1;

err:
    if (bdec) BIO_free(bdec); /* Also frees bmem if pushed */
    if (benc) {
        /* Only free if not pushed (already handled by bdec above if logic flow reached end) */
        if (BIO_next(benc) == NULL) BIO_free(benc);
    }
    if (bmem && !bdec) BIO_free(bmem);
    OPENSSL_free(plain);
    OPENSSL_free(out);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
