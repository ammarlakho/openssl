/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p3_tp1_s10_260827_133654.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    
    /* Use a size larger than ENC_MIN_CHUNK (256) to exercise internal buffering */
    unsigned char plaintext[1024];
    unsigned char ciphertext[2048];
    unsigned char decrypted[2048];
    int pt_len = 1024;
    int ct_len = 0;
    int dt_len = 0;
    BIO *bmem = NULL, *benc = NULL, *bmem_dec = NULL, *bdec = NULL;

    /* Initialize plaintext with a known pattern */
    for (int i = 0; i < pt_len; i++) {
        plaintext[i] = (unsigned char)(i & 0xFF);
    }

    /* Encryption Phase */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem)) goto err;
    
    benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(benc)) goto err;
    
    BIO_push(benc, bmem);

    if (!TEST_true(BIO_set_cipher(benc, cipher, key, iv, 1))) goto err;
    
    if (!TEST_true(BIO_write(benc, (char *)plaintext, pt_len) == pt_len)) goto err;
    
    /* Flush is mandatory for cipher BIOs to process the final block/padding */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL))) goto err;

    /* Read the resulting ciphertext from the memory BIO */
    ct_len = BIO_read(bmem, (char *)ciphertext, sizeof(ciphertext));
    if (ct_len <= 0) goto err;

    /* AES-256-CBC with PKCS7: 1024 bytes (multiple of 16) results in 1024 + 16 = 1040 bytes */
    if (!TEST_true(ct_len == 1040)) goto err;

    /* Decryption Phase */
    bmem_dec = BIO_new_mem_buf(ciphertext, ct_len);
    if (!TEST_ptr(bmem_dec)) goto err;
    
    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec)) goto err;
    
    BIO_push(bdec, bmem_dec);

    if (!TEST_true(BIO_set_cipher(bdec, cipher, key, iv, 0))) goto err;

    int n;
    while ((n = BIO_read(bdec, (char *)decrypted + dt_len, sizeof(decrypted) - dt_len)) > 0) {
        dt_len += n;
    }

    /* Verify round-trip integrity */
    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dt_len)) goto err;

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
