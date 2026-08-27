/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p6_tp1_s5_260827_142756.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    unsigned char key[32], iv[16];
    const char *plaintext = "The quick brown fox jumps over the lazy dog for BIO_f_cipher test.";
    int len = (int)strlen(plaintext);
    BIO *b_mem = NULL, *b_enc = NULL, *chain = NULL;
    BIO *b_mem_dec = NULL, *b_dec = NULL, *chain_dec = NULL;
    unsigned char *ct = NULL, *pt_res = NULL;
    int ct_len = 0, read_len = 0;

    memset(key, 0x42, sizeof(key));
    memset(iv, 0x24, sizeof(iv));

    /* Encryption phase */
    if (!TEST_ptr(b_mem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(b_enc = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(chain = BIO_push(b_enc, b_mem)))
        goto err;
    if (!TEST_true(BIO_set_cipher(chain, cipher, key, iv, 1)))
        goto err;

    if (BIO_write(chain, plaintext, len) <= 0)
        goto err;
    if (BIO_ctrl(chain, BIO_CTRL_FLUSH, 0, NULL) <= 0)
        goto err;

    /* Extract ciphertext from the memory BIO */
    ct_len = BIO_ctrl(b_mem, BIO_CTRL_PENDING, 0, NULL);
    if (ct_len <= 0)
        goto err;
    if (!TEST_ptr(ct = OPENSSL_malloc(ct_len)))
        goto err;
    if (BIO_read(b_mem, ct, ct_len) != ct_len)
        goto err;

    /* Clear encryption chain before decryption */
    BIO_free_all(chain);
    chain = NULL;

    /* Decryption phase */
    if (!TEST_ptr(b_mem_dec = BIO_new_mem_buf(ct, ct_len)))
        goto err;
    if (!TEST_ptr(b_dec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_ptr(chain_dec = BIO_push(b_dec, b_mem_dec)))
        goto err;
    if (!TEST_true(BIO_set_cipher(chain_dec, cipher, key, iv, 0)))
        goto err;

    if (!TEST_ptr(pt_res = OPENSSL_malloc(len + EVP_MAX_BLOCK_LENGTH)))
        goto err;

    /* Read decrypted data until EOF */
    while (read_len < (int)sizeof(*pt_res) && read_len < len + EVP_MAX_BLOCK_LENGTH) {
        int n = BIO_read(chain_dec, pt_res + read_len, len + EVP_MAX_BLOCK_LENGTH - read_len);
        if (n <= 0)
            break;
        read_len += n;
    }

    if (!TEST_mem_eq(plaintext, len, pt_res, read_len))
        goto err;

    BIO_free_all(chain_dec);
    OPENSSL_free(ct);
    OPENSSL_free(pt_res);
    return 1;

err:
    if (chain)
        BIO_free_all(chain);
    if (chain_dec)
        BIO_free_all(chain_dec);
    OPENSSL_free(ct);
    OPENSSL_free(pt_res);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
