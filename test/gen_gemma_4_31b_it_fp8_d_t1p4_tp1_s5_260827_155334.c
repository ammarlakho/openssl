/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p4_tp1_s5_260827_155334.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ret = 0;
    BIO *bchain_enc = NULL, *bchain_dec = NULL;
    unsigned char key[32] = {0};
    unsigned char iv[16] = {0};
    unsigned char plaintext[] = "AES-256-CBC BIO Round-trip test vector. This a balanced block size!";
    int pt_len = (int)strlen((char *)plaintext);
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    int ct_len = 0, dec_len = 0;

    /* --- Encryption phase --- */
    /* Setup: Memory BIO <- Cipher BIO */
    BIO *bmem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem_enc))
        return 0;

    BIO *bfcipher_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bfcipher_enc)) {
        BIO_free(bmem_enc);
        return 0;
    }

    if (!TEST_true(BIO_push(bfcipher_enc, bmem_enc))) {
        BIO_free_all(bfcipher_enc);
        return 0;
    }
    bchain_enc = bfcipher_enc;

    /* Initialize AES-256-CBC for encryption */
    if (!TEST_true(BIO_set_cipher(bchain_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(bchain_enc);
        return 0;
    }

    /* Write plaintext into the cipher BIO */
    if (!TEST_true(BIO_write(bchain_enc, (char *)plaintext, pt_len) == pt_len)) {
        BIO_free_all(bchain_enc);
        return 0;
    }

    /* Flush the BIO to process final block padding */
    if (!TEST_true(BIO_ctrl(bchain_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(bchain_enc);
        return 0;
    }

    /* Read result from underlying memory BIO */
    ct_len = BIO_read(bmem_enc, (char *)ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0)) {
        BIO_free_all(bchain_enc);
        return 0;
    }

    /* Fixed Vector sanity: AES-CBC ciphertext length MUST be 16-byte aligned */
    if (!TEST_true((ct_len % 16) == 0)) {
        BIO_free_all(bchain_enc);
        return 0;
    }

    /* --- Decryption phase --- */
    /* Setup: Cipher BIO -> Memory BIO (populated with ciphertext) */
    BIO *bmem_dec = BIO_new_mem_buf(ciphertext, ct_len);
    if (!TEST_ptr(bmem_dec)) {
        BIO_free_all(bchain_enc);
        return 0;
    }

    BIO *bfcipher_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bfcipher_dec)) {
        BIO_free(bmem_dec);
        BIO_free_all(bchain_enc);
        return 0;
    }

    if (!TEST_true(BIO_push(bfcipher_dec, bmem_dec))) {
        BIO_free_all(bfcipher_dec);
        BIO_free_all(bchain_enc);
        return 0;
    }
    bchain_dec = bfcipher_dec;

    /* Initialize AES-256-CBC for decryption */
    if (!TEST_true(BIO_set_cipher(bchain_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(bchain_dec);
        BIO_free_all(bchain_enc);
        return 0;
    }

    /* Read results - decrypting until EOF */
    dec_len = BIO_read(bchain_dec, (char *)decrypted, sizeof(decrypted));
    if (!TEST_true(dec_len > 0)) {
        BIO_free_all(bchain_dec);
        BIO_free_all(bchain_enc);
        return 0;
    }

    /* Compare result with origin */
    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dec_len) || (pt_len != dec_len)) {
        BIO_free_all(bchain_dec);
        BIO_free_all(bchain_enc);
        return 0;
    }

    /* Extra verification: Cipher status should be ok (1) */
    if (!TEST_true(BIO_ctrl(bchain_dec, BIO_C_GET_CIPHER_STATUS, 0, NULL) == 1)) {
        BIO_free_all(bchain_dec);
        BIO_free_all(bchain_enc);
        return 0;
    }

    BIO_free_all(bchain_dec);
    BIO_free_all(bchain_enc);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
