/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p3_tp1_s5_260827_124833.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test vectors */
    static const unsigned char key[32] = {
        0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
    };
    static const unsigned char iv[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog";
    const int pt_len = (int)sizeof(plaintext) - 1; /* no trailing NUL */

    int ok = 1;
    int outlen, tmplen;
    unsigned char ref_ct[128];
    unsigned char outbuf[256];
    unsigned char *memdata;
    long memlen;
    BIO *bmem = NULL, *bcipher = NULL;
    BIO *bsrc = NULL, *bdec = NULL;
    EVP_CIPHER_CTX *cctx = NULL;

    /* ------------------------------------------------------------
     * 1. Produce reference ciphertext using EVP API (no BIO)
     * ------------------------------------------------------------ */
    cctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(cctx))
        return 0;
    if (!TEST_int_eq(EVP_EncryptInit_ex(cctx, EVP_aes_256_cbc(),
                                        NULL, key, iv), 1))
        ok = 0;
    if (!TEST_int_eq(EVP_EncryptUpdate(cctx, ref_ct, &outlen,
                                       plaintext, pt_len), 1))
        ok = 0;
    tmplen = outlen;
    if (!TEST_int_eq(EVP_EncryptFinal_ex(cctx, ref_ct + outlen, &tmplen), 1))
        ok = 0;
    outlen += tmplen;               /* total ciphertext length */
    EVP_CIPHER_CTX_free(cctx);
    cctx = NULL;

    /* ------------------------------------------------------------
     * 2. Encrypt via BIO_f_cipher and compare with reference
     * ------------------------------------------------------------ */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        return 0;
    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher))
        return 0;
    if (!TEST_int_eq(BIO_set_cipher(bcipher, EVP_aes_256_cbc(),
                                    key, iv, 1), 1))
        ok = 0;

    /* chain: bcipher -> bmem */
    BIO_push(bcipher, bmem);

    if (!TEST_int_eq(BIO_write(bcipher, plaintext, pt_len), pt_len))
        ok = 0;
    if (!TEST_int_eq(BIO_flush(bcipher), 1))
        ok = 0;

    memlen = BIO_get_mem_data(bmem, &memdata);
    if (!TEST_long_eq(memlen, outlen))
        ok = 0;
    if (!TEST_mem_eq(memdata, (size_t)outlen, ref_ct, (size_t)outlen))
        ok = 0;

    BIO_free_all(bcipher); /* also frees bmem */

    /* ------------------------------------------------------------
     * 3. Decrypt the ciphertext via BIO_f_cipher and verify plaintext
     * ------------------------------------------------------------ */
    bsrc = BIO_new_mem_buf(ref_ct, outlen);
    if (!TEST_ptr(bsrc))
        return 0;
    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec))
        return 0;
    if (!TEST_int_eq(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                    key, iv, 0), 1))
        ok = 0;

    BIO_push(bdec, bsrc);

    outlen = 0;
    while ((tmplen = BIO_read(bdec, outbuf + outlen,
                             sizeof(outbuf) - outlen)) > 0) {
        outlen += tmplen;
    }
    if (!TEST_int_ge(tmplen, 0))   /* BIO_read should not return error */
        ok = 0;
    if (!TEST_int_eq(outlen, pt_len))
        ok = 0;
    if (!TEST_mem_eq(outbuf, (size_t)outlen,
                     plaintext, (size_t)pt_len))
        ok = 0;

    BIO_free_all(bdec); /* also frees bsrc */

    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
