/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s7_260827_130659.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ret = 1;
    const unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const unsigned char plaintext[] = "OpenSSL BIO cipher round‑trip test data";
    const int pt_len = (int)sizeof(plaintext) - 1;   /* exclude NUL */
    unsigned char *evp_ct = NULL;
    unsigned char *bio_ct = NULL;
    unsigned char *dec_pt = NULL;
    int evp_ct_len = 0, evp_final_len = 0;
    int bio_ct_len = 0;
    int total_ct_len = 0;
    int dec_len = 0, dec_final_len = 0;
    EVP_CIPHER_CTX *ectx = NULL;
    BIO *mem = NULL, *ciph = NULL;
    BIO *mem_dec = NULL, *ciph_dec = NULL;
    const char *enc_mem_ptr = NULL;
    long enc_mem_len = 0;
    int i;

    /* ---------- EVP reference encryption ---------- */
    ectx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ectx))
        return 0;
    if (!TEST_true(EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(),
                                      NULL, key, iv)))
        goto err;
    evp_ct = OPENSSL_malloc(pt_len + EVP_CIPHER_block_size(EVP_aes_256_cbc()));
    if (!TEST_ptr(evp_ct))
        goto err;
    if (!TEST_true(EVP_EncryptUpdate(ectx, evp_ct, &evp_ct_len,
                                     plaintext, pt_len)))
        goto err;
    if (!TEST_true(EVP_EncryptFinal_ex(ectx, evp_ct + evp_ct_len,
                                       &evp_final_len)))
        goto err;
    total_ct_len = evp_ct_len + evp_final_len;

    /* ---------- BIO encryption ---------- */
    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem))
        goto err;
    ciph = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(ciph))
        goto err;
    if (!TEST_true(BIO_set_cipher(ciph, EVP_aes_256_cbc(),
                                 key, iv, 1)))        /* encrypt */
        goto err;
    BIO_push(ciph, mem);
    if (!TEST_int_eq(BIO_write(ciph, plaintext, pt_len), pt_len))
        goto err;
    if (!TEST_true(BIO_flush(ciph)))
        goto err;

    /* retrieve ciphertext from memory BIO */
    enc_mem_len = BIO_get_mem_data(mem, &enc_mem_ptr);
    if (!TEST_int_eq((int)enc_mem_len, total_ct_len))
        goto err;
    bio_ct = (unsigned char *)enc_mem_ptr;   /* points into BIO internal buffer */

    /* compare BIO output with EVP reference */
    if (!TEST_mem_eq(bio_ct, total_ct_len, evp_ct, total_ct_len))
        goto err;

    /* ---------- BIO decryption ---------- */
    mem_dec = BIO_new_mem_buf(bio_ct, total_ct_len);
    if (!TEST_ptr(mem_dec))
        goto err;
    ciph_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(ciph_dec))
        goto err;
    if (!TEST_true(BIO_set_cipher(ciph_dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))        /* decrypt */
        goto err;
    BIO_push(ciph_dec, mem_dec);

    dec_pt = OPENSSL_malloc(total_ct_len);   /* plaintext will be ≤ ciphertext */
    if (!TEST_ptr(dec_pt))
        goto err;
    dec_len = BIO_read(ciph_dec, dec_pt, total_ct_len);
    if (!TEST_int_gt(dec_len, 0))
        goto err;
    /* Drain any remaining data (final block) */
    dec_final_len = BIO_read(ciph_dec, dec_pt + dec_len,
                            total_ct_len - dec_len);
    if (dec_final_len > 0)
        dec_len += dec_final_len;

    if (!TEST_int_eq(dec_len, pt_len))
        goto err;
    if (!TEST_mem_eq(dec_pt, pt_len, plaintext, pt_len))
        goto err;

    ret = 1;   /* success */

 err:
    EVP_CIPHER_CTX_free(ectx);
    OPENSSL_free(evp_ct);
    OPENSSL_free(dec_pt);
    BIO_free_all(ciph);
    BIO_free_all(mem);
    BIO_free_all(ciph_dec);
    BIO_free_all(mem_dec);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
