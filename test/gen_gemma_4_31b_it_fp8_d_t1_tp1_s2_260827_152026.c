/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1_tp1_s2_260827_152026.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    };
    unsigned char iv[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10
    };
    unsigned char pt[] = "The quick brown fox jumps over the lazy dog for BIO test";
    int pt_len = (int)strlen((char *)pt);
    unsigned char ct[256];
    unsigned char rt[256];
    int ct_len, rt_len;
    int ok = 0;

    BIO *bmem_enc = NULL, *benc = NULL, *chain_enc = NULL;
    BIO *bmem_dec = NULL, *bdec = NULL, *chain_dec = NULL;

    /* Setup Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    bmem_enc = BIO_new(BIO_s_mem());
    benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bmem_enc) || !TEST_ptr(benc))
        goto err;

    chain_enc = BIO_push(benc, bmem_enc);
    if (!TEST_ptr(chain_enc))
        goto err;

    if (!TEST_true(BIO_set_cipher(chain_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext through cipher BIO to encrypt it into memory BIO */
    if (BIO_write(chain_enc, pt, pt_len) <= 0)
        goto err;

    /* Flush is required to process the final block/padding via EVP_CipherFinal_ex */
    if (BIO_ctrl(chain_enc, BIO_CTRL_FLUSH, 0, NULL) <= 0)
        goto err;

    /* Extract ciphertext from the underlying memory BIO */
    ct_len = BIO_read(bmem_enc, ct, sizeof(ct));
    if (ct_len <= 0)
        goto err;

    /* Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem */
    bmem_dec = BIO_new(BIO_s_mem());
    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bmem_dec) || !TEST_ptr(bdec))
        goto err;

    chain_dec = BIO_push(bdec, bmem_dec);
    if (!TEST_ptr(chain_dec))
        goto err;

    /* Write the extracted ciphertext into the decryption source memory BIO */
    if (BIO_write(bmem_dec, ct, ct_len) <= 0)
        goto err;

    if (!TEST_true(BIO_set_cipher(chain_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read through cipher BIO to decrypt */
    rt_len = BIO_read(chain_dec, rt, sizeof(rt));
    if (rt_len <= 0)
        goto err;

    /* Verify the round-trip result matches original plaintext */
    ok = TEST_mem_eq(pt, pt_len, rt, rt_len);

err:
    if (chain_enc)
        BIO_free_all(chain_enc);
    if (chain_dec)
        BIO_free_all(chain_dec);
    
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
