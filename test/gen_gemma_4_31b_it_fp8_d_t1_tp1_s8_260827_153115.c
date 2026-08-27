/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s8_260827_153115.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 1;
    BIO *bmem = NULL, *benc = NULL, *bdec = NULL;
    unsigned char key[32], iv[16];
    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog. OpenSSL BIO test!";
    int plen = (int)sizeof(plaintext) - 1;
    unsigned char ciphertext[128];
    int clen = 0;
    unsigned char decrypted[128];
    int dlen = 0;

    /* Setup key and IV */
    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* Step 1: Encryption round-trip */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem())))) {
        ok = 0;
        goto end;
    }
    if (!TEST_ptr((benc = BIO_new(BIO_f_cipher())))) {
        ok = 0;
        goto end;
    }
    if (!TEST_true(BIO_push(benc, bmem))) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1))) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(BIO_write(benc, (char *)plaintext, plen) == plen)) {
        ok = 0;
        goto end;
    }

    /* Flush is critical for block ciphers to process padding */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL))) {
        ok = 0;
        goto end;
    }

    clen = BIO_read(bmem, (char *)ciphertext, sizeof(ciphertext));
    if (clen <= 0) {
        ok = 0;
        goto end;
    }

    /* Step 2: Decryption round-trip */
    /* Create a new memory BIO containing the ciphertext */
    BIO *bmem_in = BIO_new_mem_buf(ciphertext, clen);
    if (!TEST_ptr(bmem_in)) {
        ok = 0;
        goto end;
    }
    if (!TEST_ptr((bdec = BIO_new(BIO_f_cipher())))) {
        BIO_free(bmem_in);
        ok = 0;
        goto end;
    }
    if (!TEST_true(BIO_push(bdec, bmem_in))) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0))) {
        ok = 0;
        goto end;
    }

    dlen = BIO_read(bdec, (char *)decrypted, sizeof(decrypted));
    if (dlen <= 0) {
        ok = 0;
        goto end;
    }

    if (!TEST_mem_eq(plaintext, plen, decrypted, dlen)) {
        ok = 0;
    }

end:
    if (benc) BIO_free_all(benc);
    if (bdec) BIO_free_all(bdec);
    if (bmem && !benc) BIO_free(bmem);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
