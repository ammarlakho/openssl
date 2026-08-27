/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s3_260827_132444.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
{
    /* Test vectors */
    static const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f
    };
    const char plaintext[] = "OpenSSL BIO Cipher round‑trip test vector 1234567890";
    const size_t pt_len = sizeof(plaintext) - 1; /* exclude NUL */

    /* -----------------------------------------------------------------
     * 1. Produce the reference ciphertext using the EVP API
     * ----------------------------------------------------------------- */
    EVP_CIPHER_CTX *evp = EVP_CIPHER_CTX_new();
    unsigned char ref_ct[pt_len + EVP_MAX_BLOCK_LENGTH];
    int outlen1 = 0, outlen2 = 0;
    unsigned char *ref_ct_ptr = ref_ct;
    size_t ref_ct_len = 0;

    if (!TEST_ptr(evp))
        return 0;
    if (!TEST_true(EVP_EncryptInit_ex(evp, EVP_aes_256_cbc(),
                                      NULL, key, iv)))
        goto end;
    if (!TEST_true(EVP_EncryptUpdate(evp,
                                      ref_ct_ptr, &outlen1,
                                      (const unsigned char *)plaintext,
                                      (int)pt_len)))
        goto end;
    if (!TEST_true(EVP_EncryptFinal_ex(evp,
                                       ref_ct_ptr + outlen1, &outlen2)))
        goto end;
    ref_ct_len = (size_t)(outlen1 + outlen2);

    /* -----------------------------------------------------------------
     * 2. Encrypt via BIO_f_cipher and compare with reference ciphertext
     * ----------------------------------------------------------------- */
    BIO *mem_enc = BIO_new(BIO_s_mem());
    BIO *benc = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_enc) || !TEST_ptr(benc))
        goto end;

    if (!TEST_true(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* 1 = encrypt */
        goto end;
    BIO_push(benc, mem_enc);

    if (!TEST_int_eq(BIO_write(benc, plaintext, (int)pt_len), (int)pt_len))
        goto end;
    if (!TEST_true(BIO_flush(benc)))
        goto end;

    char *bio_ct = NULL;
    long bio_ct_len = BIO_get_mem_data(mem_enc, &bio_ct);
    if (!TEST_long_eq(bio_ct_len, (long)ref_ct_len))
        goto end;
    if (!TEST_mem_eq(bio_ct, (size_t)bio_ct_len, ref_ct, ref_ct_len))
        goto end;

    /* -----------------------------------------------------------------
     * 3. Decrypt the BIO‑generated ciphertext and verify original plaintext
     * ----------------------------------------------------------------- */
    BIO *mem_dec = BIO_new_mem_buf(bio_ct, (int)bio_ct_len);
    BIO *bdec = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_dec) || !TEST_ptr(bdec))
        goto end;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* 0 = decrypt */
        goto end;
    BIO_push(bdec, mem_dec);

    unsigned char dec_out[sizeof(plaintext)]; /* big enough */
    size_t dec_total = 0;
    int r;

    while ((r = BIO_read(bdec, dec_out + dec_total,
                        (int)(sizeof(dec_out) - dec_total))) > 0) {
        dec_total += (size_t)r;
        if (dec_total > sizeof(dec_out))
            break;  /* should never happen */
    }
    if (!TEST_int_ge(r, 0))          /* error on the last read */
        goto end;
    if (!TEST_size_t_eq(dec_total, pt_len))
        goto end;
    if (!TEST_mem_eq(dec_out, pt_len, plaintext, pt_len))
        goto end;

    /* -----------------------------------------------------------------
     * 4. Cleanup and success
     * ----------------------------------------------------------------- */
    BIO_free_all(benc);   /* also frees mem_enc */
    BIO_free_all(bdec);   /* also frees mem_dec */
    EVP_CIPHER_CTX_free(evp);
    return 1;

end:
    BIO_free_all(benc);
    BIO_free_all(bdec);
    EVP_CIPHER_CTX_free(evp);
    return 0;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
