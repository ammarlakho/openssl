/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s3_260827_130455.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
static int test_bio_enc_generated(void)
{
    int ok = 1;
    /* Fixed key/IV (incrementing byte values) */
    const unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    const unsigned char iv[16] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
        0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
    };

    const unsigned char plaintext[] = "OpenSSL BIO cipher test vector";
    const size_t plaintext_len = sizeof(plaintext) - 1;

    /* -----------------------------------------------------------------
     * 1. Compute the expected ciphertext using the EVP API.
     * ----------------------------------------------------------------- */
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    unsigned char evp_ct[128];
    int evp_outlen1 = 0, evp_outlen2 = 0;

    if (!TEST_ptr(evp_ctx))
        return 0;
    if (!TEST_true(EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(),
                                     NULL, key, iv)))
        ok = 0;
    if (!TEST_true(EVP_EncryptUpdate(evp_ctx, evp_ct, &evp_outlen1,
                                     plaintext, (int)plaintext_len)))
        ok = 0;
    if (!TEST_true(EVP_EncryptFinal_ex(evp_ctx,
                                       evp_ct + evp_outlen1, &evp_outlen2)))
        ok = 0;
    EVP_CIPHER_CTX_free(evp_ctx);
    const int evp_ct_len = evp_outlen1 + evp_outlen2;

    /* -----------------------------------------------------------------
     * 2. Encrypt via the cipher BIO and compare with the EVP result.
     * ----------------------------------------------------------------- */
    BIO *mem = BIO_new(BIO_s_mem());
    BIO *benc = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem) || !TEST_ptr(benc))
        return 0;
    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* encrypt */
        ok = 0;

    BIO_push(benc, mem);
    if (BIO_write(benc, plaintext, (int)plaintext_len) != (int)plaintext_len)
        ok = 0;
    if (!TEST_true(BIO_flush(benc)))
        ok = 0;

    /* Extract ciphertext from the memory BIO */
    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(mem, &bptr);
    if (!TEST_ptr(bptr))
        ok = 0;

    /* Make a private copy before freeing the BIO chain */
    unsigned char *ciphertext = NULL;
    if (bptr && bptr->length > 0) {
        ciphertext = OPENSSL_memdup(bptr->data, bptr->length);
        if (!TEST_ptr(ciphertext))
            ok = 0;
    }

    /* Compare lengths and contents */
    if (!TEST_int_eq(bptr ? bptr->length : -1, evp_ct_len))
        ok = 0;
    if (!TEST_mem_eq(bptr ? bptr->data : NULL,
                     bptr ? bptr->length : 0,
                     evp_ct, evp_ct_len))
        ok = 0;

    /* Clean up the encryption chain (mem is freed by BIO_free_all) */
    BIO_free_all(benc);

    /* -----------------------------------------------------------------
     * 3. Decrypt the ciphertext via a cipher BIO and verify it matches
     *    the original plaintext.
     * ----------------------------------------------------------------- */
    if (!ciphertext)
        return 0;   /* cannot continue without ciphertext */

    BIO *mem_in = BIO_new_mem_buf(ciphertext, (int)bptr->length);
    BIO *bdec   = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_in) || !TEST_ptr(bdec))
        ok = 0;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* decrypt */
        ok = 0;

    BIO_push(bdec, mem_in);

    unsigned char dec_out[128];
    int total_read = 0, r = 0;
    while ((r = BIO_read(bdec, dec_out + total_read,
                        (int)sizeof(dec_out) - total_read)) > 0) {
        total_read += r;
        if (total_read >= (int)sizeof(dec_out))
            break;
    }
    if (!TEST_int_gt(total_read, 0))
        ok = 0;
    if (!TEST_int_eq(total_read, (int)plaintext_len))
        ok = 0;
    if (!TEST_mem_eq(dec_out, total_read, plaintext, plaintext_len))
        ok = 0;

    BIO_free_all(bdec);
    OPENSSL_free(ciphertext);
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
