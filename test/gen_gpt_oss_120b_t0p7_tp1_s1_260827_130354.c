/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p7_tp1_s1_260827_130354.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vector */
    static const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static const unsigned char plaintext[] =
        "OpenSSL BIO cipher round‑trip test data";

    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    EVP_CIPHER_CTX *cctx = NULL;
    unsigned char exp_ct[128];
    unsigned char *enc_data = NULL;
    long enc_len = 0;
    unsigned char dec_buf[128];
    int outlen = 0, tmplen = 0;
    int i, total = 0;
    BIO *bmem = NULL, *bcipher = NULL, *bsrc = NULL, *bdec = NULL;
    int ret = 0; /* assume failure */

    /* ------------------------------------------------------------
     * 1. Produce expected ciphertext using the EVP API directly.
     * ------------------------------------------------------------ */
    if (!TEST_ptr(cctx = EVP_CIPHER_CTX_new()))
        goto end;
    if (!TEST_true(EVP_CipherInit_ex(cctx, cipher, NULL, key, iv, 1)))
        goto end;
    if (!TEST_true(EVP_CipherUpdate(cctx, exp_ct, &outlen,
                                   plaintext, (int)sizeof(plaintext)-1)))
        goto end;
    tmplen = outlen;
    if (!TEST_true(EVP_CipherFinal_ex(cctx, exp_ct + outlen, &outlen)))
        goto end;
    tmplen += outlen;               /* total ciphertext length */

    EVP_CIPHER_CTX_free(cctx);
    cctx = NULL;

    /* ------------------------------------------------------------
     * 2. Encrypt via BIO_f_cipher and compare with expected ciphertext.
     * ------------------------------------------------------------ */
    if (!TEST_ptr(bmem = BIO_new(BIO_s_mem())))
        goto end;
    if (!TEST_ptr(bcipher = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(bcipher, cipher, key, iv, 1)))
        goto end;
    /* chain: bcipher -> bmem */
    bcipher = BIO_push(bcipher, bmem);
    bmem = NULL; /* now owned by bcipher */

    if (!TEST_int_eq(BIO_write(bcipher,
                               plaintext,
                               (int)sizeof(plaintext)-1),
                     (int)sizeof(plaintext)-1))
        goto end;
    if (!TEST_int_eq(BIO_flush(bcipher), 1))
        goto end;

    /* obtain encrypted data from the memory BIO */
    if (!TEST_int_ge(BIO_get_mem_data(bcipher, &enc_data), 0))
        goto end;
    enc_len = BIO_get_mem_data(bcipher, &enc_data);
    if (!TEST_int_eq((int)enc_len, tmplen))
        goto end;
    if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                     exp_ct,   (size_t)tmplen))
        goto end;

    /* ------------------------------------------------------------
     * 3. Decrypt the ciphertext via BIO_f_cipher and verify plaintext.
     * ------------------------------------------------------------ */
    bsrc = BIO_new_mem_buf(enc_data, (int)enc_len);
    if (!TEST_ptr(bsrc))
        goto end;
    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec))
        goto end;
    if (!TEST_true(BIO_set_cipher(bdec, cipher, key, iv, 0)))
        goto end;
    bdec = BIO_push(bdec, bsrc);
    bsrc = NULL; /* now owned by bdec */

    /* read all decrypted data */
    while ((i = BIO_read(bdec, dec_buf + total,
                         (int)sizeof(dec_buf) - total)) > 0) {
        total += i;
    }
    if (!TEST_int_eq(total, (int)sizeof(plaintext)-1))
        goto end;
    if (!TEST_mem_eq(dec_buf, (size_t)total,
                     plaintext, (size_t)sizeof(plaintext)-1))
        goto end;

    /* all checks passed */
    ret = 1;

end:
    BIO_free_all(bdec);
    BIO_free_all(bcipher);
    EVP_CIPHER_CTX_free(cctx);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
