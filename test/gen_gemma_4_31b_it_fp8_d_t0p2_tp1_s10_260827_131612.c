/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p2_tp1_s10_260827_131612.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                              0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                              0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plaintext_len = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    int ciphertext_len = 0;
    unsigned char decrypted[128];
    int decrypted_len = 0;
    BIO *bmem = NULL, *benc = NULL, *bdec = NULL;

    if (!TEST_ptr(cipher))
        return 0;

    /* Encryption phase: Plaintext -> Cipher BIO -> Mem BIO */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((benc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;
    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(benc, plaintext, plaintext_len) > 0))
        goto err;
    /* BIO_CTRL_FLUSH is required to trigger EVP_CipherFinal_ex and write padding */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract the resulting ciphertext from the underlying memory BIO */
    ciphertext_len = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (!TEST_true(ciphertext_len > 0))
        goto err;
    /* AES-CBC with padding should result in a length that is a multiple of 16 */
    if (!TEST_true(ciphertext_len % 16 == 0))
        goto err;

    /* Decryption phase: Mem BIO (ciphertext) -> Cipher BIO -> Output */
    BIO *bmem_dec = BIO_new_mem_buf(ciphertext, ciphertext_len);
    if (!TEST_ptr(bmem_dec))
        goto err;
    if (!TEST_ptr((bdec = BIO_new(BIO_f_cipher())))) {
        BIO_free(bmem_dec);
        goto err;
    }
    if (!TEST_true(BIO_push(bdec, bmem_dec)))
        goto err;
    if (!TEST_true(BIO_set_cipher(bdec, cipher, key, iv, 0)))
        goto err;

    decrypted_len = BIO_read(bdec, decrypted, sizeof(decrypted));
    if (!TEST_true(decrypted_len == plaintext_len))
        goto err;
    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, decrypted_len))
        goto err;

    BIO_free_all(bdec);
    BIO_free_all(benc);
    return 1;

err:
    if (benc) BIO_free_all(benc);
    if (bdec) BIO_free_all(bdec);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
