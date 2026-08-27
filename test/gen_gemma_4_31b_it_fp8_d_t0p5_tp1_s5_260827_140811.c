/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t0p5_tp1_s5_260827_140811.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    unsigned char key[32];
    unsigned char iv[16];
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    int plain_len = (int)strlen(plaintext);
    unsigned char ciphertext[1024];
    unsigned char decrypted[1024];
    int enc_len, dec_len;
    BIO *b_mem_enc = NULL, *b_cipher_enc = NULL;
    BIO *b_mem_dec = NULL, *b_cipher_dec = NULL;
    int ret = 0;

    /* Initialize key and IV with fixed vectors */
    memset(key, 0x01, sizeof(key));
    memset(iv, 0x02, sizeof(iv));

    /* --- Encryption Path --- */
    /* Create a chain: BIO_f_cipher (encrypt) -> BIO_s_mem (sink) */
    if (!TEST_ptr((b_mem_enc = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_cipher_enc = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher_enc, b_mem_enc)))
        goto err;

    /* Set up AES-256-CBC for encryption */
    if (!TEST_true(BIO_set_cipher(b_cipher_enc, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    /* Write plaintext through the cipher BIO */
    if (!TEST_true(BIO_write(b_cipher_enc, plaintext, plain_len) == plain_len))
        goto err;

    /* Flush to ensure EVP_CipherFinal_ex is called and padding is written to the sink */
    if (!TEST_true(BIO_ctrl(b_cipher_enc, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Read the resulting ciphertext from the memory BIO */
    enc_len = BIO_read(b_mem_enc, ciphertext, sizeof(ciphertext));
    if (enc_len <= 0)
        goto err;

    /* --- Decryption Path --- */
    /* Create a chain: BIO_f_cipher (decrypt) -> BIO_s_mem (source) */
    if (!TEST_ptr((b_mem_dec = BIO_new(BIO_s_mem()))))
        goto err;
    if (!TEST_ptr((b_cipher_dec = BIO_new(BIO_f_cipher()))))
        goto err;
    if (!TEST_true(BIO_push(b_cipher_dec, b_mem_dec)))
        goto err;

    /* Load the ciphertext into the memory BIO source */
    if (!TEST_true(BIO_write(b_mem_dec, ciphertext, enc_len) == enc_len))
        goto err;
    BIO_set_mem_offset(b_mem_dec, 0);

    /* Set up AES-256-CBC for decryption */
    if (!TEST_true(BIO_set_cipher(b_cipher_dec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    /* Read from the cipher BIO to decrypt */
    dec_len = BIO_read(b_cipher_dec, decrypted, sizeof(decrypted));
    if (dec_len < 0)
        goto err;

    /* Flush to trigger decryption of the final block/padding */
    if (!TEST_true(BIO_ctrl(b_cipher_dec, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Read remaining decrypted bytes */
    int final_dec = BIO_read(b_cipher_dec, decrypted + dec_len, sizeof(decrypted) - dec_len);
    if (final_dec < 0)
        goto err;
    dec_len += final_dec;

    /* Verify the round-trip result matches the original plaintext */
    if (!TEST_mem_eq(plaintext, plain_len, decrypted, dec_len))
        goto err;

    ret = 1;

err:
    if (b_cipher_enc)
        BIO_free_all(b_cipher_enc);
    if (b_cipher_dec)
        BIO_free_all(b_cipher_dec);

    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
