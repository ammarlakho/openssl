/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_sonnet_remedium_r3_260828_010519.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    static const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char iv[16] = {
        0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
        0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
    };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog. "
        "Pack my box with five dozen liquor jugs.";
    const int ptlen = (int)(sizeof(plaintext) - 1);

    unsigned char expected_ct[256];
    int exp_ct_len = 0, exp_final_len = 0;
    unsigned char dec_buf[256];
    int dec_len = 0, dec_final_len = 0;

    EVP_CIPHER_CTX *ectx = NULL;
    BIO *cbio = NULL, *mbio = NULL;
    long ctlen;
    unsigned char *ctdata = NULL;
    unsigned char readback[256];
    int n, ret = 0;

    /* Compute expected ciphertext directly via EVP as fixed reference */
    if (!TEST_ptr(ectx = EVP_CIPHER_CTX_new()))
        goto end;
    if (!TEST_true(EVP_EncryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, key, iv)))
        goto end;
    if (!TEST_true(EVP_EncryptUpdate(ectx, expected_ct, &exp_ct_len,
                                      plaintext, ptlen)))
        goto end;
    if (!TEST_true(EVP_EncryptFinal_ex(ectx, expected_ct + exp_ct_len,
                                        &exp_final_len)))
        goto end;
    exp_ct_len += exp_final_len;
    EVP_CIPHER_CTX_free(ectx);
    ectx = NULL;

    /* Now encrypt the same plaintext through the BIO_f_cipher filter */
    if (!TEST_ptr(mbio = BIO_new(BIO_s_mem())))
        goto end;
    if (!TEST_ptr(cbio = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(cbio, EVP_aes_256_cbc(), key, iv, 1)))
        goto end;
    BIO_push(cbio, mbio);

    if (!TEST_int_eq(BIO_write(cbio, plaintext, ptlen), ptlen))
        goto end;
    if (!TEST_int_ge(BIO_flush(cbio), 0))
        goto end;
    if (!TEST_true(BIO_get_cipher_status(cbio)))
        goto end;

    ctlen = BIO_get_mem_data(mbio, &ctdata);
    if (!TEST_int_eq((int)ctlen, exp_ct_len))
        goto end;
    if (!TEST_mem_eq(ctdata, (int)ctlen, expected_ct, exp_ct_len))
        goto end;

    /* Round-trip: decrypt the produced ciphertext back through a new BIO chain */
    BIO_free(cbio);
    cbio = NULL;
    mbio = NULL; /* freed as part of chain */

    if (!TEST_ptr(mbio = BIO_new_mem_buf(ctdata, (int)ctlen)))
        goto end;
    if (!TEST_ptr(cbio = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(cbio, EVP_aes_256_cbc(), key, iv, 0)))
        goto end;
    BIO_push(cbio, mbio);

    n = BIO_read(cbio, readback, sizeof(readback));
    if (!TEST_int_ge(n, 0))
        goto end;
    if (n < ptlen) {
        int n2 = BIO_read(cbio, readback + n, (int)sizeof(readback) - n);

        if (n2 > 0)
            n += n2;
    }
    if (!TEST_true(BIO_get_cipher_status(cbio)))
        goto end;
    if (!TEST_int_eq(n, ptlen))
        goto end;
    if (!TEST_mem_eq(readback, n, plaintext, ptlen))
        goto end;

    /* Cross-check against direct EVP decryption as another fixed comparison */
    if (!TEST_ptr(ectx = EVP_CIPHER_CTX_new()))
        goto end;
    if (!TEST_true(EVP_DecryptInit_ex(ectx, EVP_aes_256_cbc(), NULL, key, iv)))
        goto end;
    if (!TEST_true(EVP_DecryptUpdate(ectx, dec_buf, &dec_len,
                                      expected_ct, exp_ct_len)))
        goto end;
    if (!TEST_true(EVP_DecryptFinal_ex(ectx, dec_buf + dec_len,
                                        &dec_final_len)))
        goto end;
    dec_len += dec_final_len;
    if (!TEST_int_eq(dec_len, ptlen))
        goto end;
    if (!TEST_mem_eq(dec_buf, dec_len, plaintext, ptlen))
        goto end;

    ret = 1;

end:
    EVP_CIPHER_CTX_free(ectx);
    BIO_free(cbio);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
