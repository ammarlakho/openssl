/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p6_tp1_s10_260827_143738.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 1;
    BIO *bmem = NULL, *benc = NULL, *bmem_dec = NULL, *bdec = NULL;
    unsigned char *ct = NULL;
    unsigned char res[256];
    int ct_len, rd_len;

    /* AES-256 CBC test vectors */
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
    const char *pt = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(pt);

    /* 1. Encryption: Plaintext -> BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        return 0;
    if (!TEST_ptr((benc = BIO_new(BIO_f_cipher())))) {
        BIO_free(bmem);
        return 0;
    }
    if (!TEST_true(BIO_push(benc, bmem))) {
        BIO_free(benc);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free(benc);
        return 0;
    }

    if (!TEST_true(BIO_write(benc, pt, pt_len) > 0)) {
        BIO_free(benc);
        return 0;
    }

    /* Finalize encryption (padding) */
    if (!TEST_true(BIO_ctrl(benc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free(benc);
        return 0;
    }

    ct_len = BIO_ctrl_pending(bmem);
    if (ct_len <= 0) {
        BIO_free(benc);
        return 0;
    }

    ct = OPENSSL_malloc(ct_len);
    if (ct == NULL) {
        BIO_free(benc);
        return 0;
    }
    BIO_read(bmem, ct, ct_len);
    BIO_free(benc); /* frees bmem too */

    /* 2. Decryption: BIO_s_mem (buf) -> BIO_f_cipher -> Result */
    if (!TEST_ptr((bmem_dec = BIO_new_mem_buf(ct, ct_len)))) {
        OPENSSL_free(ct);
        return 0;
    }
    if (!TEST_ptr((bdec = BIO_new(BIO_f_cipher())))) {
        BIO_free(bmem_dec);
        OPENSSL_free(ct);
        return 0;
    }
    if (!TEST_true(BIO_push(bdec, bmem_dec))) {
        BIO_free(bdec);
        BIO_free(bmem_dec);
        OPENSSL_free(ct);
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free(bdec);
        OPENSSL_free(ct);
        return 0;
    }

    rd_len = BIO_read(bdec, res, sizeof(res));
    if (rd_len <= 0) {
        ok = 0;
    } else {
        if (!TEST_mem_eq(pt, pt_len, res, rd_len)) {
            ok = 0;
        }
    }

    BIO_free(bdec);
    OPENSSL_free(ct);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
