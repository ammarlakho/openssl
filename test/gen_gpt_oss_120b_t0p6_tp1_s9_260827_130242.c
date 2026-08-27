/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p6_tp1_s9_260827_130242.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vectors */
    static const unsigned char key[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
    };
    static const unsigned char iv[16] = {
        0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
        0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
    };
    static const unsigned char plaintext[] =
        "OpenSSL BIO cipher filter test vector – non‑multiple block size.";
    const size_t pt_len = sizeof(plaintext) - 1; /* omit trailing NUL */

    BIO *mem = NULL, *enc = NULL;
    BUF_MEM *bptr = NULL;
    unsigned char *enc_buf = NULL;
    int enc_len = 0;

    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char *expected = NULL;
    int out1 = 0, out2 = 0, expected_len = 0;

    BIO *mem2 = NULL, *dec = NULL;
    unsigned char *dec_out = NULL;
    int total = 0;
    long cipher_status = 0;

    /* ---------- encryption via BIO ---------- */
    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto end;
    if (!TEST_ptr(enc = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))          /* encrypt */
        goto end;
    BIO_push(enc, mem);

    if (!TEST_int_eq(BIO_write(enc, (const char *)plaintext,
                               (int)pt_len), (int)pt_len))
        goto end;
    if (!TEST_int_eq(BIO_flush(enc), 1))
        goto end;

    if (!TEST_true(BIO_get_mem_ptr(mem, &bptr)))
        goto end;
    enc_buf = (unsigned char *)bptr->data;
    enc_len = bptr->length;

    /* ---------- expected ciphertext using EVP directly ---------- */
    cctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(cctx))
        goto end;
    if (!TEST_true(EVP_CipherInit_ex(cctx, EVP_aes_256_cbc(),
                                     NULL, key, iv, 1)))   /* encrypt */
        goto end;
    expected = OPENSSL_malloc(pt_len + EVP_MAX_BLOCK_LENGTH);
    if (!TEST_ptr(expected))
        goto end;
    if (!TEST_true(EVP_CipherUpdate(cctx, expected, &out1,
                                    plaintext, (int)pt_len)))
        goto end;
    if (!TEST_true(EVP_CipherFinal_ex(cctx, expected + out1, &out2)))
        goto end;
    EVP_CIPHER_CTX_free(cctx);
    cctx = NULL;
    expected_len = out1 + out2;

    if (!TEST_mem_eq(enc_buf, enc_len, expected, expected_len))
        goto end;

    /* ---------- decryption via BIO ---------- */
    dec_out = OPENSSL_malloc(expected_len);
    if (!TEST_ptr(dec_out))
        goto end;
    if (!TEST_ptr(mem2 = BIO_new_mem_buf(enc_buf, enc_len)))
        goto end;
    if (!TEST_ptr(dec = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))          /* decrypt */
        goto end;
    BIO_push(dec, mem2);

    /* Read until EOF */
    while (1) {
        int r = BIO_read(dec, dec_out + total,
                         (int)expected_len - total);
        if (r > 0) {
            total += r;
            continue;
        }
        if (BIO_should_retry(dec))
            continue;
        break;
    }

    if (!TEST_int_eq(total, (int)pt_len))
        goto end;
    if (!TEST_mem_eq(dec_out, total, plaintext, pt_len))
        goto end;

    /* Verify cipher status flag */
    if (!TEST_true(BIO_ctrl(dec, BIO_C_GET_CIPHER_STATUS, 0,
                           (void *)&cipher_status)))
        goto end;
    if (!TEST_int_eq((int)cipher_status, 1))
        goto end;

    ok = 1;   /* all checks passed */

end:
    if (cctx)
        EVP_CIPHER_CTX_free(cctx);
    OPENSSL_free(expected);
    OPENSSL_free(dec_out);
    BIO_free_all(enc);   /* frees enc and mem */
    BIO_free_all(dec);   /* frees dec and mem2 */
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
