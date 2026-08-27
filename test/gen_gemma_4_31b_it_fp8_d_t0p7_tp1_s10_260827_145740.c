/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p7_tp1_s10_260827_145740.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_mem = NULL, *b_enc = NULL;
    unsigned char key[32], iv[16];
    unsigned char plaintext[] = "OpenSSL";
    int pltxt_len = (int)strlen((char *)plaintext);
    unsigned char ciphertext[] = {
        0xf5, 0xa4, 0x86, 0x46, 0xd9, 0x4a, 0x32, 0xa7,
        0x30, 0x8f, 0xd3, 0xc6, 0x78, 0x4a, 0xd5, 0x41
    };
    int ctxt_len = 16;
    unsigned char out[64];
    int out_len;

    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    for (int i = 0; i < 16; i++) iv[i] = (unsigned char)i;

    /* --- Encryption Test --- */
    if (!TEST_ptr(b_mem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(b_enc = BIO_push(BIO_f_cipher(), b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, (char *)plaintext, pltxt_len) == pltxt_len))
        goto err;

    /* Flush is required to process the final block/padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL) == 1))
        goto err;

    out_len = BIO_read(b_mem, (char *)out, ctxt_len);
    if (!TEST_mem_eq(out, out_len, ciphertext, ctxt_len))
        goto err;

    BIO_free(b_enc);
    b_enc = b_mem = NULL;

    /* --- Decryption Test --- */
    if (!TEST_ptr(b_mem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(b_enc = BIO_push(BIO_f_cipher(), b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Write ciphertext into the underlying memory BIO */
    if (!TEST_true(BIO_write(b_mem, (char *)ciphertext, ctxt_len) == ctxt_len))
        goto err;

    /* Read from cipher BIO to decrypt */
    out_len = BIO_read(b_enc, (char *)out, sizeof(out));
    
    /* Flush to get the final decrypted block (removing padding) */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL) == 1))
        goto err;

    int final_len = BIO_read(b_enc, (char *)out + out_len, sizeof(out) - out_len);
    out_len += final_len;

    if (!TEST_mem_eq(out, out_len, plaintext, pltxt_len))
        goto err;

    ret = 1;

err:
    if (b_enc)
        BIO_free(b_enc);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
