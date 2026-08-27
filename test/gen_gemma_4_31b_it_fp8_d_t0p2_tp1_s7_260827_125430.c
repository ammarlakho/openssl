/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p2_tp1_s7_260827_125430.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *b_mem_enc = NULL, *b_cipher_enc = NULL;
    BIO *b_mem_dec = NULL, *b_cipher_dec = NULL;
    unsigned char key[32], iv[16], plaintext[64], ciphertext[128], decrypted[128];
    unsigned char golden_ct[128];
    int pt_len, ct_len, dec_len;
    EVP_CIPHER_CTX *evp_ctx = NULL;

    /* Setup test vectors */
    pt_len = 64;
    memset(key, 0x41, sizeof(key));
    memset(iv, 0x42, sizeof(iv));
    memset(plaintext, 0x43, pt_len);

    /* 1. Generate "Golden" ciphertext using EVP API directly to verify BIO wrapper */
    evp_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(evp_ctx))
        return 0;

    if (!EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(), NULL, key, iv))
        goto err;

    int len = 0;
    if (!EVP_EncryptUpdate(evp_ctx, golden_ct, &len, plaintext, pt_len))
        goto err;
    ct_len = len;
    if (!EVP_EncryptFinal_ex(evp_ctx, golden_ct + len, &len))
        goto err;
    ct_len += len;
    EVP_CIPHER_CTX_free(evp_ctx);
    evp_ctx = NULL;

    /* 2. Encryption Path: Plaintext -> BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr(b_mem_enc = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(b_cipher_enc = BIO_new(BIO_f_cipher())))
        goto err;

    if (!TEST_true(BIO_push(b_cipher_enc, b_mem_enc)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_cipher_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(b_cipher_enc, (char *)plaintext, pt_len) == pt_len))
        goto err;

    /* Flush is critical to trigger EVP_CipherFinal_ex in bio_enc.c */
    if (!TEST_true(BIO_ctrl(b_cipher_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from memory BIO */
    unsigned char *ct_ptr = NULL;
    long bio_ct_len = BIO_get_mem_data(b_mem_enc, &ct_ptr);
    if (!TEST_true(bio_ct_len == ct_len))
        goto err;
    if (!TEST_mem_eq(ct_ptr, bio_ct_len, golden_ct, ct_len))
        goto err;

    memcpy(ciphertext, ct_ptr, ct_len);

    /* 3. Decryption Path: BIO_s_mem (with ciphertext) -> BIO_f_cipher -> Plaintext */
    if (!TEST_ptr(b_mem_dec = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_true(BIO_write(b_mem_dec, (char *)ciphertext, ct_len) == ct_len))
        goto err;

    if (!TEST_ptr(b_cipher_dec = BIO_new(BIO_f_cipher())))
        goto err;
    if (!TEST_true(BIO_push(b_cipher_dec, b_mem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(b_cipher_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    dec_len = BIO_read(b_cipher_dec, (char *)decrypted, sizeof(decrypted));
    if (!TEST_true(dec_len == pt_len))
        goto err;
    if (!TEST_mem_eq(decrypted, dec_len, plaintext, pt_len))
        goto err;

    ok = 1;

err:
    if (evp_ctx)
        EVP_CIPHER_CTX_free(evp_ctx);
    if (b_cipher_enc)
        BIO_free_all(b_cipher_enc);
    if (b_cipher_dec)
        BIO_free_all(b_cipher_dec);

    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
