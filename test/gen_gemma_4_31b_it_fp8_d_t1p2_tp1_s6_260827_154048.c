/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s6_260827_154048.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_mem = NULL, *b_enc = NULL, *b_dec = NULL;
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog. 1234567890!";
    int pt_len = (int)sizeof(pt) - 1;
    unsigned char ct[256];
    unsigned char recovered[256];
    int ct_len = 0, rec_len = 0;
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                              0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
                              0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                              0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20 };
    unsigned char iv[16] = { 0 };

    /* Setup encryption chain: b_enc (cipher) -> b_mem (memory) */
    if (!TEST_ptr((b_mem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_enc, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_enc, (const char *)pt, pt_len) > 0))
        goto err;

    /* Flush is critical to force EVP_CipherFinal (padding) to the underlying BIO */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* In BIO_s_mem, a write creates a buffer. Let's see how much we wrote. */
    ct_len = BIO_read(b_mem, (char *)ct, sizeof(ct));
    if (ct_len <= 0)
        goto err;

    /* Reset the memory BIO to read from the start for decryption */
    if (!TEST_true(BIO_reset(b_mem)))
        goto err;

    /* Setup decryption chain: b_dec (cipher) -> b_mem (memory) */
    if (!TEST_ptr((b_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_dec, b_mem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read back from the decryption BIO */
    rec_len = BIO_read(b_dec, (char *)recovered, sizeof(recovered));
    if (rec_len <= 0)
        goto err;

    if (!TEST_mem_eq(pt, pt_len, recovered, rec_len))
        goto err;

    ok = 1;

err:
    BIO_free_all(b_enc);
    BIO_free_all(b_dec);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
