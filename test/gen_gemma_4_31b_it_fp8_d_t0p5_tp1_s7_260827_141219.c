/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p5_tp1_s7_260827_141219.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int pt_len = (int)strlen(plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len = 0;
    int dec_len = 0;
    int ret = 0;

    BIO *bmem = NULL, *bcipher = NULL, *chain = NULL;
    BIO *bmem_dec = NULL, *bcipher_dec = NULL, *chain_dec = NULL;

    /* Encryption phase */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((bcipher = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((chain = BIO_push(bcipher, bmem))))
        goto err;

    if (!TEST_true(BIO_set_cipher(chain, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(chain, plaintext, pt_len) == pt_len))
        goto err;

    /* Flush is required to process padding and final block */
    if (!TEST_true(BIO_ctrl(chain, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from the underlying memory BIO */
    ct_len = BIO_read(bmem, ciphertext, sizeof(ciphertext));
    if (ct_len <= 0)
        goto err;

    /* Decryption phase */
    if (!TEST_ptr((bmem_dec = BIO_new_mem_buf(ciphertext, ct_len))))
        goto err;
    if (!TEST_ptr((bcipher_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_ptr((chain_dec = BIO_push(bcipher_dec, bmem_dec))))
        goto err;

    if (!TEST_true(BIO_set_cipher(chain_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read decrypted data */
    dec_len = BIO_read(chain_dec, decrypted, sizeof(decrypted));
    if (dec_len <= 0)
        goto err;

    /* Verify round-trip */
    if (!TEST_mem_eq(plaintext, pt_len, decrypted, dec_len))
        goto err;

    ret = 1;

err:
    if (chain)
        BIO_free(chain);
    if (chain_dec)
        BIO_free(chain_dec);

    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
