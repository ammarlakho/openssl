/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p4_tp1_s10_260827_160109.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    /*
     * Test case: AES-256-CBC round-trip encryption and decryption using BIO_f_cipher.
     * Validates that a plaintext written to an encrypting filter BIO is 
     * correctly recovered when readout through a decrypting filter BIO.
     */
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                              0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                              0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const char *plaintext = "The quick brown fox jumps over the lazy dog. OpenSSL BIO cipher тест.";
    int plain_len = (int)strlen(plaintext);
    unsigned char decrypted[256];
    int dec_len = 0;
    int ret;

    BIO *bmem = NULL, *bc = NULL;

    /* 1. Setup Encryption Chain: Cipher Filter -> Memory BIO */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        goto err;

    if (!TEST_ptr((bc = BIO_new(BIO_f_cipher()))))
        goto err;

    if (!TEST_true(BIO_push(bc, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext to filter BIO, which encrypts it and pushes to memory BIO */
    ret = BIO_write(bc, plaintext, plain_len);
    if (!TEST_true(ret == plain_len))
        goto err;

    /* Flush is mandatory to finalize the encryption (padding) and write the final block */
    if (!TEST_true(BIO_ctrl(bc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* 2. Setup Decryption Chain: Cipher Filter -> Memory BIO ( Reuse same bmem ) */
    /* Pop the encryption filter so we can attach a decryption one to the same memory BIO */
    BIO_pop(bc);
    BIO_free(bc);
    bc = NULL;

    if (!TEST_ptr((bc = BIO_new(BIO_f_cipher()))))
        goto err;

    if (!TEST_true(BIO_push(bc, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bc, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read from the cipher filter BIO, which decrypts data read from memory BIO */
    while (dec_len < (int)sizeof(decrypted)) {
        int r = BIO_read(bc, (char *)(decrypted + dec_len), (int)sizeof(decrypted) - dec_len);
        if (r <= 0)
            break;
        dec_len += r;
    }

    /* Validating decryption result */
    if (!TEST_true(dec_len == plain_len))
        goto err;

    if (!TEST_mem_eq(plaintext, plain_len, decrypted, dec_len))
        goto err;

    /* Check that the decryption was successful via the cipher status control */
    if (!TEST_true(BIO_ctrl(bc, BIO_C_GET_CIPHER_STATUS, 0, NULL) == 1))
        goto err;

    BIO_free_all(bc);
    return 1;

err:
    if (bc) BIO_free_all(bc);
    else if (bmem) BIO_free(bmem);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
