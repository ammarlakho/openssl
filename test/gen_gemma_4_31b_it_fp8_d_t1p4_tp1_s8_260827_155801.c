/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p4_tp1_s8_260827_155801.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 1;
    BIO *enc_bio = NULL, *dec_bio = NULL, *mem_bio = NULL;
    unsigned char key[32], iv[16];
    unsigned char plaintext[] = "The quick brown fox jumps over the lazy dog - OpenSSL BIO test";
    int pltxt_len = (int)strlen((char *)plaintext);
    unsigned char ciphertext[128];
    unsigned char decrypted[128];
    int ct_len, dt_len;

    /* Setup keys and IV (fixed vectors for reproducibility) */
    memset(key, 0x42, sizeof(key));
    memset(iv, 0x13, sizeof(iv));

    /* 1. Encryption Process: Plaintext -> BIO_f_cipher -> BIO_s_mem */
    enc_bio = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc_bio)) goto err;

    mem_bio = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem_bio)) goto err;

    if (!TEST_true(BIO_push(enc_bio, mem_bio)))
        goto err;

    if (!TEST_true(BIO_set_cipher(enc_bio, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext and flush to trigger EVP_CipherFinal_ex */
    if (!TEST_true(BIO_write(enc_bio, (char *)plaintext, pltxt_len) > 0))
        goto err;
    if (!TEST_true(BIO_ctrl(enc_bio, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Extract ciphertext from the underlying memory BIO */
    ct_len = BIO_read(mem_bio, (char *)ciphertext, sizeof(ciphertext));
    if (!TEST_true(ct_len > 0))
        goto err;

    /* 2. Decryption Process: ciphertext -> BIO_f_cipher -> BIO_s_mem -> Plaintext */
    /* We reuse a memory BIO to feed the ciphertext into the decrypting filter */
    BIO *sink_bio = BIO_new(BIO_s_mem());
    if (!TEST_ptr(sink_bio)) goto err;

    dec_bio = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec_bio)) goto err;

    /* Wrap the memory BIO containing our ciphertext */
    BIO *src_mem_bio = BIO_new(BIO_s_mem());
    if (!TEST_ptr(src_mem_bio)) goto err;
    BIO_write(src_mem_bio, (char *)ciphertext, ct_len);

    if (!TEST_true(BIO_push(dec_bio, src_mem_bio)))
        goto err;

    if (!TEST_true(BIO_set_cipher(dec_bio, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read back the decrypted content */
    dt_len = BIO_read(dec_bio, (char *)decrypted, sizeof(decrypted));
    if (!TEST_true(dt_len > 0))
        goto err;

    /* Verify identity */
    if (!TEST_true(dt_len == pltxt_len)) {
        ok = 0;
        goto err;
    }
    if (!TEST_mem_eq(plaintext, pltxt_len, decrypted, dt_len)) {
        ok = 0;
        goto err;
    }

    BIO_free_all(enc_bio);
    BIO_free_all(dec_bio);
    BIO_free_all(sink_bio);
    return 1;

err:
    if (enc_bio) BIO_free_all(enc_bio);
    if (dec_bio) BIO_free_all(dec_bio);
    if (sink_bio) BIO_free_all(sink_bio);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
