/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p8_tp1_s3_260827_150332.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *bmem_out = NULL, *benc = NULL, *bchain_enc = NULL;
    BIO *bmem_in = NULL, *bdec = NULL, *bchain_dec = NULL;
    const unsigned char key[32] = "01234567890123456789012345678901";
    const unsigned char iv[16] = "0123456789012345";
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plength = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char recovered[128];
    int clen = 0, rlen = 0;

    /* Encryption Phase */
    if (!TEST_ptr(bmem_out = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(benc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(bchain_enc = BIO_push(benc, bmem_out)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bchain_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(bchain_enc, plaintext, plength) == plength))
        goto err;

    /* Flush to ensure padding is written to the underlying BIO */
    if (!TEST_true(BIO_ctrl(bchain_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract the ciphertext from the memory BIO */
    clen = BIO_read(bmem_out, (char *)ciphertext, (int)sizeof(ciphertext));
    if (clen <= 0)
        goto err;

    /* Decryption Phase */
    if (!TEST_ptr(bmem_in = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_true(BIO_write(bmem_in, (const char *)ciphertext, clen) == clen))
        goto err;

    if (!TEST_ptr(bdec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(bchain_dec = BIO_push(bdec, bmem_in)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bchain_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    rlen = BIO_read(bchain_dec, (char *)recovered, (int)sizeof(recovered));
    if (rlen < 0)
        goto err;

    /* Finalize decryption (handles padding) */
    if (!TEST_true(BIO_ctrl(bchain_dec, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    int final_read = BIO_read(bchain_dec, (char *)recovered + rlen, (int)sizeof(recovered) - rlen);
    if (final_read < 0)
        goto err;
    rlen += final_read;

    if (!TEST_true(rlen == plength))
        goto err;

    if (!TEST_mem_eq(plaintext, plength, recovered, rlen))
        goto err;

    ok = 1;

err:
    BIO_free_all(bchain_enc);
    BIO_free_all(bchain_dec);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
