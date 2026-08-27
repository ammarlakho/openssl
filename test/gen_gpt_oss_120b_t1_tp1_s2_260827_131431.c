/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s2_260827_131431.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    /*
     * Test AES‑256‑CBC BIO filter by encrypting a known plaintext,
     * comparing the result with the same operation performed via the
     * EVP API, then decrypting the ciphertext and checking that the
     * original plaintext is recovered.
     */
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const unsigned char plaintext[] =
        "OpenSSL BIO test vector for AES-256 CBC mode!";
    const int plen = (int)sizeof(plaintext) - 1; /* omit terminating NUL */

    unsigned char evp_ct[256];
    unsigned char evp_pt[256];
    int outlen1, outlen2, expected_len, decrypted_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    BIO *bmem = NULL, *bcipher = NULL, *bchain = NULL;
    BIO *src = NULL, *bdec = NULL, *bdec_chain = NULL;
    unsigned char *bio_ct = NULL;
    long bio_ct_len = 0;
    int ret = 0;

    /* ----------------------------------------------------------------- *
     * 1️⃣  Produce the expected ciphertext using the EVP API directly.
     * ----------------------------------------------------------------- */
    ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ctx))
        goto out;
    if (!TEST_true(EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(),
                                    NULL, key, iv)))
        goto out;
    if (!TEST_true(EVP_EncryptUpdate(ctx, evp_ct, &outlen1,
                                    plaintext, plen)))
        goto out;
    if (!TEST_true(EVP_EncryptFinal_ex(ctx, evp_ct + outlen1, &outlen2)))
        goto out;
    expected_len = outlen1 + outlen2;
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* ----------------------------------------------------------------- *
     * 2️⃣  Encrypt via the BIO_f_cipher filter and compare with EVP output.
     * ----------------------------------------------------------------- */
    bmem = BIO_new(BIO_s_mem());
    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bmem) || !TEST_ptr(bcipher))
        goto out;
    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* 1 = encrypt */
        goto out;

    bchain = BIO_push(bcipher, bmem);          /* cipher -> mem */
    if (!TEST_int_gt(BIO_write(bchain, plaintext, plen), 0))
        goto out;
    if (!TEST_true(BIO_flush(bchain)))        /* push final block */
        goto out;

    bio_ct_len = BIO_get_mem_data(bmem, &bio_ct);
    if (!TEST_int_eq(bio_ct_len, expected_len))
        goto out;
    if (!TEST_mem_eq(bio_ct, (size_t)bio_ct_len,
                     evp_ct, (size_t)expected_len))
        goto out;

    /* ----------------------------------------------------------------- *
     * 3️⃣  Decrypt the ciphertext via the BIO_f_cipher filter and verify.
     * ----------------------------------------------------------------- */
    src = BIO_new_mem_buf(bio_ct, (int)bio_ct_len);
    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(src) || !TEST_ptr(bdec))
        goto out;
    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* 0 = decrypt */
        goto out;

    bdec_chain = BIO_push(bdec, src);          /* cipher -> memsource */
    /* Read until we have retrieved the whole plaintext */
    while ((ret = BIO_read(bdec_chain,
                          evp_pt + decrypted_len,
                          plen + EVP_MAX_BLOCK_LENGTH - decrypted_len)) > 0) {
        decrypted_len += ret;
    }
    if (!TEST_int_gt(decrypted_len, 0))
        goto out;
    if (!TEST_int_eq(decrypted_len, plen))
        goto out;
    if (!TEST_mem_eq(evp_pt, (size_t)decrypted_len,
                     plaintext, (size_t)plen))
        goto out;

    /* All checks passed */
    return 1;

out:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    BIO_free_all(bchain);
    BIO_free_all(bdec_chain);
    return 0;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
