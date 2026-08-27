/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p2_tp1_s2_260827_124119.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32];
    unsigned char iv[16];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    BIO *bmem = NULL, *bcipher = NULL;
    int cipher_len = 0, dec_len = 0, r = 0;

    /* Initialize key and IV with fixed values */
    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted, 0, sizeof(decrypted));

    /* Setup BIO chain: Cipher Filter -> Memory BIO */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        return 0;
    if (!TEST_ptr((bcipher = BIO_new(BIO_f_cipher())))) {
        BIO_free(bmem);
        return 0;
    }
    if (!TEST_true(BIO_push(bcipher, bmem))) {
        BIO_free(bcipher);
        return 0;
    }

    /* 1. Encryption Phase */
    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free(bcipher);
        return 0;
    }

    if (!TEST_true(BIO_write(bcipher, plaintext, plain_len) > 0)) {
        BIO_free(bcipher);
        return 0;
    }

    /* Flush is required to process the final block/padding */
    if (!TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL) == 1)) {
        BIO_free(bcipher);
        return 0;
    }

    /* Extract ciphertext from the memory BIO */
    cipher_len = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_true(cipher_len > 0)) {
        BIO_free(bcipher);
        return 0;
    }

    /* 2. Decryption Phase */
    /* Reset memory BIO to read the ciphertext back from the start */
    if (!TEST_true(BIO_reset(bmem))) {
        BIO_free(bcipher);
        return 0;
    }

    /* Reconfigure cipher BIO for decryption */
    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free(bcipher);
        return 0;
    }

    /* Read from cipher BIO until EOF (which triggers EVP_CipherFinal_ex internally) */
    while ((r = BIO_read(bcipher, decrypted + dec_len, sizeof(decrypted) - dec_len)) > 0) {
        dec_len += r;
    }

    /* Verify the round-trip result */
    if (!TEST_mem_eq(plaintext, plain_len, decrypted, dec_len)) {
        BIO_free(bcipher);
        return 0;
    }

    BIO_free(bcipher);
    return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
