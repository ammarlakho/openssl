/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s2_260827_153607.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *benc = NULL, *bdec = NULL, *bmem = NULL;
    unsigned char key[32], iv[16], ciphertext[128], decrypted[128];
    const char *plain = "Hello OpenSSL BIO Cipher Test! This is a round-trip check.";
    int plain_len = (int)strlen(plain);
    int cipher_len = 0;
    int dec_len = 0;

    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));
    memset(ciphertext, 0, sizeof(ciphertext));
    memset(decrypted, 0, sizeof(decrypted));

    /* -- Encryption Side -- */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        return 0;

    benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(benc))
        goto err;

    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(benc, plain, plain_len) > 0))
        goto err;

    /* Flush is critical to trigger EVP_CipherFinal and push padding */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL) > 0))
        goto err;

    char *ptr = NULL;
    cipher_len = (int)BIO_get_mem_data(bmem, &ptr);
    if (cipher_len <= 0 || ptr == NULL)
        goto err;

    memcpy(ciphertext, ptr, cipher_len);
    BIO_free_all(benc);
    benc = NULL;

    /* -- Decryption Side -- */
    /* Create a source BIO with the ciphertext */
    BIO *bmem_in = BIO_new_mem_buf(ciphertext, cipher_len);
    if (!TEST_ptr(bmem_in))
        goto err;

    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec)) {
        BIO_free(bmem_in);
        goto err;
    }

    if (!TEST_true(BIO_push(bdec, bmem_in)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    dec_len = BIO_read(bdec, (char *)decrypted, sizeof(decrypted) - 1);
    if (dec_len <= 0)
        goto err;
    decrypted[dec_len] = '\0';

    if (!TEST_mem_eq((unsigned char *)plain, plain_len, decrypted, dec_len))
        goto err;

    ok = 1;

err:
    if (benc) BIO_free_all(benc);
    if (bdec) BIO_free_all(bdec);
    /* bmem is handled by BIO_free_all(benc) if pushed, 
        but we check if it's still standalone here implicitly */
    if (bmem && !benc) BIO_free(bmem);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
