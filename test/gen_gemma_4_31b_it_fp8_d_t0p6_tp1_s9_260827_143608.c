/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p6_tp1_s9_260827_143608.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *bmem = NULL, *bcipher = NULL;
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plen = (int)strlen(plaintext);
    unsigned char decrypted[128];
    int rlen;

    /* 1. Setup BIO chain: Cipher Filter -> Memory Sink */
    TEST_ptr(bmem = BIO_new(BIO_s_mem()));
    if (bmem == NULL) return 0;

    TEST_ptr(bcipher = BIO_new(BIO_f_cipher()));
    if (bcipher == NULL) {
        BIO_free(bmem);
        return 0;
    }

    TEST_true(BIO_push(bcipher, bmem));

    /* 2. Encrypt */
    TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 1));
    
    /* Write plaintext through the cipher BIO */
    int wlen = BIO_write(bcipher, plaintext, plen);
    TEST_true(wlen == plen);

    /* Flush to ensure the final padded block is written to bmem */
    TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL));

    /* 3. Prepare for Decryption */
    /* Reset the memory BIO read pointer to the beginning */
    BIO_set_mem_offset(bmem, 0);

    /* Re-initialize the cipher BIO for decryption */
    TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 0));

    /* 4. Decrypt */
    memset(decrypted, 0, sizeof(decrypted));
    rlen = BIO_read(bcipher, (char *)decrypted, sizeof(decrypted));
    
    /* Verify round-trip */
    TEST_true(rlen == plen);
    TEST_mem_eq(plaintext, plen, decrypted, rlen);

    BIO_free_all(bcipher);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
