/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p6_tp1_s7_260827_143159.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char pt[] = "OpenSSL";
    int pt_len = (int)strlen((char *)pt);
    /* AES-256-CBC, PKCS#7 padding, Key=0, IV=0, PT="OpenSSL" */
    unsigned char expected_ct[] = {
        0xf4, 0x43, 0x83, 0xe6, 0x19, 0x66, 0x57, 0x58,
        0x79, 0x98, 0x71, 0x51, 0x45, 0x4c, 0xf4, 0x72
    };
    int ct_len = sizeof(expected_ct);

    BIO *b_mem = NULL, *b_enc = NULL;
    unsigned char actual_ct[64];
    int written, read_ct, actual_ct_len = 0;

    /* --- Encryption Phase --- */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        return 0;
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher())))) {
        BIO_free(b_mem);
        return 0;
    }
    if (!TEST_true(BIO_push(b_enc, b_mem))) {
        BIO_free_all(b_enc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(b_enc);
        return 0;
    }

    written = BIO_write(b_enc, pt, pt_len);
    if (!TEST_true(written == pt_len)) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Flush to trigger EVP_CipherFinal_ex */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(b_enc);
        return 0;
    }

    /* Read ciphertext from the memory BIO */
    read_ct = BIO_read(b_mem, actual_ct, sizeof(actual_ct));
    if (!TEST_true(read_ct == ct_len)) {
        BIO_free_all(b_enc);
        return 0;
    }
    if (!TEST_mem_eq(actual_ct, ct_len, expected_ct, ct_len)) {
        BIO_free_all(b_enc);
        return 0;
    }
    BIO_free_all(b_enc);

    /* --- Decryption Phase --- */
    BIO *b_mem_in = NULL, *b_dec = NULL;
    unsigned char actual_pt[64];
    int read_pt;

    if (!TEST_ptr((b_mem_in = BIO_new_mem_buf(expected_ct, ct_len))))
        return 0;
    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher())))) {
        BIO_free(b_mem_in);
        return 0;
    }
    if (!TEST_true(BIO_push(b_dec, b_mem_in))) {
        BIO_free_all(b_dec);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(b_dec);
        return 0;
    }

    /* Read decrypted plaintext */
    read_pt = BIO_read(b_dec, actual_pt, sizeof(actual_pt));
    if (!TEST_true(read_pt == pt_len)) {
        BIO_free_all(b_dec);
        return 0;
    }
    if (!TEST_mem_eq(actual_pt, pt_len, pt, pt_len)) {
        BIO_free_all(b_dec);
        return 0;
    }

    BIO_free_all(b_dec);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
