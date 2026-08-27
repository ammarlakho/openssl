/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p2_tp1_s1_260827_123835.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *bmem = NULL, *bcipher = NULL;
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                              0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                              0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20 };
    unsigned char iv[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                             0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    unsigned char plain[] = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen((char *)plain);
    unsigned char cipher[128];
    unsigned char decrypted[128];
    int cipher_len, dec_len, n;

    /* 1. Setup BIO chain: Cipher Filter -> Memory BIO */
    if (!TEST_ptr((bmem = BIO_new(BIO_s_mem()))))
        return 0;
    if (!TEST_ptr((bcipher = BIO_new(BIO_f_cipher())))) {
        BIO_free(bmem);
        return 0;
    }
    if (!TEST_true(BIO_push(bcipher, bmem))) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* 2. Encryption Phase */
    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free_all(bcipher);
        return 0;
    }

    if (!TEST_true(BIO_write(bcipher, (char *)plain, plain_len) == plain_len)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Flush to ensure padding is written to the memory BIO */
    if (!TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(bcipher);
        return 0;
    }

    cipher_len = BIO_read(bmem, (char *)cipher, sizeof(cipher));
    if (!TEST_true(cipher_len > 0)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Verify that ciphertext is actually different from plaintext */
    if (!TEST_true(memcmp(plain, cipher, plain_len) != 0)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* 3. Decryption Phase */
    /* Reset memory BIO to read the ciphertext back from the start */
    BIO_reset(bmem);

    if (!TEST_true(BIO_set_cipher(bcipher, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Write the ciphertext into the memory BIO so the cipher filter can read it */
    if (!TEST_true(BIO_write(bmem, (char *)cipher, cipher_len) == cipher_len)) {
        BIO_free_all(bcipher);
        return 0;
    }

    /* Reset memory BIO again to allow the cipher filter to read the data we just wrote */
    BIO_reset(bmem);

    dec_len = 0;
    while (dec_len < (int)sizeof(decrypted)) {
        n = BIO_read(bcipher, (char *)decrypted + dec_len, (int)sizeof(decrypted) - dec_len);
        if (n <= 0)
            break;
        dec_len += n;
    }

    /* Final flush to handle any remaining buffered decrypted data */
    if (!TEST_true(BIO_ctrl(bcipher, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free_all(bcipher);
        return 0;
    }
    n = BIO_read(bcipher, (char *)decrypted + dec_len, (int)sizeof(decrypted) - dec_len);
    if (n > 0)
        dec_len += n;

    /* 4. Final Verification */
    int result = TEST_mem_eq(plain, plain_len, decrypted, dec_len);
    BIO_free_all(bcipher);
    return result;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
