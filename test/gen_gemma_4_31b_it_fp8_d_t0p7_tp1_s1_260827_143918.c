/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s1_260827_143918.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
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
    unsigned char plain[] = "The quick brown fox jumps over the lazy dog for BIO_f_cipher test!";
    size_t plain_len = strlen((char *)plain);
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    int ct_len, pt_len, r;
    BIO *enc_chain = NULL, *mem_out = NULL, *mem_in = NULL, *dec_chain = NULL;

    /* --- Encryption Phase --- */
    enc_chain = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc_chain))
        return 0;

    mem_out = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem_out)) {
        BIO_free(enc_chain);
        return 0;
    }

    if (!TEST_ptr(BIO_push(enc_chain, mem_out))) {
        BIO_free_all(enc_chain);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(enc_chain, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(enc_chain);
        return 0;
    }

    if (!TEST_true(BIO_write(enc_chain, (const char *)plain, (int)plain_len) == (int)plain_len)) {
        BIO_free_all(enc_chain);
        return 0;
    }

    /* Flush is required to trigger EVP_CipherFinal_ex and write padding */
    if (!TEST_true(BIO_ctrl(enc_chain, BIO_CTRL_FLUSH, 0, NULL) > 0)) {
        BIO_free_all(enc_chain);
        return 0;
    }

    /* Read ciphertext from the memory BIO */
    ct_len = BIO_read(mem_out, (char *)ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0)) {
        BIO_free_all(enc_chain);
        return 0;
    }
    BIO_free_all(enc_chain);

    /* --- Decryption Phase --- */
    mem_in = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem_in))
        return 0;

    /* Put ciphertext into the memory BIO */
    if (!TEST_true(BIO_write(mem_in, (const char *)ciphertext, ct_len) == ct_len)) {
        BIO_free(mem_in);
        return 0;
    }

    dec_chain = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec_chain)) {
        BIO_free(mem_in);
        return 0;
    }

    if (!TEST_ptr(BIO_push(dec_chain, mem_in))) {
        BIO_free_all(dec_chain);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(dec_chain, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(dec_chain);
        return 0;
    }

    pt_len = 0;
    while ((r = BIO_read(dec_chain, (char *)decrypted + pt_len, sizeof(decrypted) - pt_len)) > 0) {
        pt_len += r;
    }

    if (!TEST_true(pt_len == (int)plain_len)) {
        BIO_free_all(dec_chain);
        return 0;
    }

    if (!TEST_mem_eq(plain, plain_len, decrypted, pt_len)) {
        BIO_free_all(dec_chain);
        return 0;
    }

    BIO_free_all(dec_chain);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
