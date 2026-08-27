/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p2_tp1_s8_260827_132209.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Fixed test vectors */
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
    const char plaintext[] = "Test vector for BIO_f_cipher encryption";
    size_t plainlen = sizeof(plaintext) - 1; /* exclude NUL */
    unsigned char *ciphertext = NULL;
    size_t cipherlen = 0;
    int ret = 1;

    /* ---------- Encryption via BIO_f_cipher ---------- */
    BIO *bmem_enc = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem_enc))
        return 0;
    BIO *benc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(benc))
        return 0;
    if (!TEST_int_eq(BIO_set_cipher(benc, EVP_aes_256_cbc(),
                                    key, iv, 1), 1))
        ret = 0;
    BIO_push(benc, bmem_enc);

    if (BIO_write(benc, plaintext, (int)plainlen) != (int)plainlen)
        ret = 0;
    if (BIO_flush(benc) <= 0)
        ret = 0;

    /* Obtain the ciphertext from the memory BIO */
    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bmem_enc, &bptr);
    if (!TEST_ptr(bptr))
        ret = 0;
    if (bptr && bptr->length > 0) {
        ciphertext = (unsigned char *)OPENSSL_memdup(bptr->data,
                                                     bptr->length);
        if (!TEST_ptr(ciphertext))
            ret = 0;
        cipherlen = bptr->length;
    } else {
        ret = 0;
    }

    BIO_free_all(benc); /* also frees bmem_enc */

    if (!ret)
        return 0;

    /* ---------- Decryption via BIO_f_cipher ---------- */
    BIO *bmem_dec = BIO_new_mem_buf(ciphertext, (int)cipherlen);
    if (!TEST_ptr(bmem_dec))
        return 0;
    BIO *bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec))
        return 0;
    if (!TEST_int_eq(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                    key, iv, 0), 1))
        ret = 0;
    BIO_push(bdec, bmem_dec);

    unsigned char outbuf[1024];
    int outlen = BIO_read(bdec, outbuf, sizeof(outbuf));
    if (outlen <= 0)
        ret = 0;
    else {
        /* The output length should match the original plaintext length */
        if (!TEST_int_eq(outlen, (int)plainlen))
            ret = 0;
        if (!TEST_mem_eq(outbuf, outlen,
                         (const unsigned char *)plaintext, plainlen))
            ret = 0;
    }

    BIO_free_all(bdec);
    OPENSSL_free(ciphertext);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
