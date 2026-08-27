/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s6_260827_145017.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    const char *plaintext = "The quick brown fox jumps over the lazy dog. This is a test of BIO_f_cipher!";
    int plaintext_len = (int)strlen(plaintext);
    unsigned char decrypted[256];
    int read_len = 0;
    BIO *bmem = NULL, *benc = NULL, *bdec = NULL, *bmem_in = NULL;
    unsigned char *ciphertext = NULL;
    long ciphertext_len = 0;

    /* Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((benc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(benc, plaintext, plaintext_len) == plaintext_len))
        goto err;

    /* Flush to process final padding block */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from memory BIO */
    ciphertext_len = BIO_get_mem_data(bmem, &ciphertext);
    if (ciphertext_len <= 0)
        goto err;

    /* Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem (containing ciphertext) */
    if (!TEST_ptr((bmem_in = BIO_new_mem_buf(ciphertext, (unsigned int)ciphertext_len))))
        goto err;
    if (!TEST_ptr((bdec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(bdec, bmem_in)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    read_len = BIO_read(bdec, (char *)decrypted, sizeof(decrypted));
    if (read_len != plaintext_len)
        goto err;

    if (!TEST_mem_eq(plaintext, plaintext_len, decrypted, read_len))
        goto err;

    BIO_free_all(benc);
    BIO_free_all(bdec);
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
