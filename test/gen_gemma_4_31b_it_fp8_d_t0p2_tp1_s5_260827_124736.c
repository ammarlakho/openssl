/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p2_tp1_s5_260827_124736.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 0;
    BIO *b_mem = NULL, *b_cipher = NULL;
    BIO *b_mem_dec = NULL, *b_cipher_dec = NULL;
    unsigned char key[32], iv[16];
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen((char *)pt);
    unsigned char ct[128], dec[128];
    int ct_len = 0, dec_len = 0;

    /* Setup fixed key and IV */
    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    for (int i = 0; i < 16; i++) iv[i] = (unsigned char)i;

    /* 1. Encryption Path: PT -> BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_cipher = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_cipher, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_cipher, (const char *)pt, pt_len) > 0))
        goto err;

    /* Flush is required to trigger EVP_CipherFinal_ex and write padding */
    if (!TEST_true(BIO_ctrl(b_cipher, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from the memory BIO */
    ct_len = BIO_read(b_mem, (char *)ct, sizeof(ct));
    if (ct_len <= 0)
        goto err;

    /* Verify that ciphertext is actually different from plaintext */
    if (TEST_true(memcmp(pt, ct, pt_len) != 0)) {
        /* This is expected */
    } else {
        goto err;
    }

    /* 2. Decryption Path: BIO_s_mem (CT) -> BIO_f_cipher -> PT_dec */
    if (!TEST_ptr((b_mem_dec = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_true(BIO_write(b_mem_dec, (const char *)ct, ct_len) > 0))
        goto err;

    if (!TEST_ptr((b_cipher_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_cipher_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    dec_len = BIO_read(b_cipher_dec, (char *)dec, sizeof(dec));
    if (dec_len <= 0)
        goto err;

    /* Final flush to ensure all blocks are processed */
    BIO_ctrl(b_cipher_dec, BIO_CTRL_FLUSH, 0, NULL);

    /* 3. Verification */
    if (!TEST_true(dec_len == pt_len))
        goto err;
    if (!TEST_mem_eq(pt, pt_len, dec, dec_len))
        goto err;

    ok = 1;

err:
    BIO_free_all(b_cipher);
    BIO_free_all(b_cipher_dec);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
