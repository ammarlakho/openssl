/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s1_260827_134009.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    int len = (int)strlen(plaintext);
    unsigned char decrypted[128];
    int read_len = 0;
    int ret = 0;

    BIO *bmem_out = NULL;
    BIO *benc = NULL;
    BIO *bmem_in = NULL;
    BIO *bdec = NULL;

    for (int i = 0; i < 32; i++) key[i] = (unsigned char)i;
    for (int i = 0; i < 16; i++) iv[i] = (unsigned char)i;

    /* Encryption phase */
    if (!TEST_ptr((bmem_out = BIO_new(BIO_s_mem()))))
        goto err;

    if (!TEST_ptr((benc = BIO_push(bmem_out, BIO_f_cipher()))))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (BIO_write(benc, plaintext, len) <= 0)
        goto err;

    if (BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL) <= 0)
        goto err;

    BUF_MEM *bptr = BIO_get_mem_data(bmem_out);
    if (!TEST_ptr(bptr))
        goto err;

    /* Decryption phase */
    if (!TEST_ptr((bmem_in = BIO_new(BIO_s_mem()))))
        goto err;

    if (BIO_write(bmem_in, bptr->data, bptr->length) <= 0)
        goto err;

    if (!TEST_ptr((bdec = BIO_push(bmem_in, BIO_f_cipher()))))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    read_len = BIO_read(bdec, (char *)decrypted, len);
    if (read_len <= 0)
        goto err;

    ret = TEST_mem_eq(plaintext, len, decrypted, read_len);

err:
    BIO_free_all(benc);
    BIO_free_all(bdec);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
