/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p4_tp1_s4_260827_134643.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen((char *)pt);
    unsigned char key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    BIO *bmem = NULL, *benc = NULL;
    char *ct_ptr = NULL;
    long ct_len = 0;
    int ret = 0;

    /* --- Encryption Phase --- */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((benc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(benc, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(benc, pt, pt_len) == pt_len))
        goto err;

    /* Flush to handle padding and finalize encryption */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL) == 1))
        goto err;

    ct_len = BIO_get_mem_data(bmem, &ct_ptr);
    if (!TEST_true(ct_len > 0))
        goto err;

    /* --- Decryption Phase --- */
    BIO *bmem_in = NULL, *bdec = NULL;
    unsigned char res[256];
    int read_len = 0;

    if (!TEST_ptr((bmem_in = BIO_new_mem_buf(ct_ptr, ct_len))))
        goto err;
    if (!TEST_ptr((bdec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(bdec, bmem_in)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    while (read_len < (int)sizeof(res)) {
        int n = BIO_read(bdec, res + read_len, (int)sizeof(res) - read_len);
        if (n <= 0)
            break;
        read_len += n;
    }

    if (!TEST_true(read_len == pt_len))
        goto err;

    if (!TEST_mem_eq(pt, pt_len, res, read_len))
        goto err;

    ret = 1;

err:
    if (benc)
        BIO_free(benc);
    if (bdec)
        BIO_free(bdec);

    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
