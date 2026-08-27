/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p4_tp1_s4_260827_155213.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *bi_enc = NULL, *bi_dec = NULL, *bi_mem = NULL;
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                               0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                               0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                               0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const char *plaintext = "This is a test for BIO_f_cipher using AES-256 CBC mode.";
    int pl_len = (int)strlen(plaintext);
    unsigned char encrypted[128];
    unsigned char decrypted[128];
    int enc_len = 0, dec_len = 0;

    /* Step 1: Encryption Round Trip */
    bi_mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bi_mem)) {
        ok = 0;
        goto end;
    }

    bi_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bi_enc)) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(BIO_push(bi_enc, bi_mem))) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(BIO_set_cipher(bi_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(BIO_write(bi_enc, plaintext, pl_len) > 0)) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(BIO_ctrl(bi_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        ok = 0;
        goto end;
    }

    /* Extract ciphertext from the underlying memory BIO */
    enc_len = BIO_read(bi_mem, encrypted, sizeof(encrypted));
    if (enc_len <= 0) {
        ok = 0;
        goto end;
    }

    /* Separate cleanup of encryption chain for fresh decryption test */
    BIO_free_all(bi_enc);
    bi_enc = NULL;

    /* Step 2: Decryption Round Trip */
    /* use the encrypted data as a memory buffer */
    bi_mem = BIO_new_mem_buf(encrypted, enc_len);
    if (!TEST_ptr(bi_mem)) {
        ok = 0;
        goto end;
    }

    bi_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bi_dec)) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(BIO_push(bi_dec, bi_mem))) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(BIO_set_cipher(bi_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        ok = 0;
        goto end;
    }

    dec_len = BIO_read(bi_dec, decrypted, sizeof(decrypted));
    if (dec_len <= 0) {
        ok = 0;
        goto end;
    }

    if (!TEST_mem_eq(plaintext, pl_len, decrypted, dec_len)) {
        ok = 0;
        goto end;
    }

    if (!TEST_true(dec_len == pl_len)) {
        ok = 0;
        goto end;
    }

end:
    BIO_free_all(bi_enc);
    BIO_free_all(bi_dec);
    /* bi_mem is handled by the chains above if they are not NULL */
    
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
