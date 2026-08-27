/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s3_260827_131502.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test AES‑256‑CBC encryption/decryption using the BIO_f_cipher filter */
    const unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const unsigned char iv[16] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
        0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
    };
    const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog";
    const int plaintext_len = (int)sizeof(plaintext) - 1;   /* exclude NUL */

    BIO *mem = NULL;          /* memory BIO that will hold ciphertext */
    BIO *enc = NULL;          /* encryption filter BIO */
    BIO *src = NULL;          /* memory BIO that holds ciphertext for decryption */
    BIO *dec = NULL;          /* decryption filter BIO */
    char *cipher_buf = NULL;  /* pointer returned by BIO_get_mem_data */
    long cipher_len = 0;
    unsigned char *decrypted = NULL;
    int ret = 0;
    int i, n;

    /* ---------- encrypt ---------- */
    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto end;
    if (!TEST_ptr(enc = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))   /* 1 → encrypt */
        goto end;
    BIO_push(enc, mem);                     /* enc -> mem */

    if (!TEST_int_eq(BIO_write(enc,
                               (const char *)plaintext,
                               plaintext_len), plaintext_len))
        goto end;
    if (!TEST_true(BIO_flush(enc)))        /* finalize encryption */
        goto end;

    /* obtain ciphertext from the memory BIO */
    cipher_len = BIO_get_mem_data(mem, &cipher_buf);
    if (!TEST_true(cipher_len > 0))
        goto end;

    /* ---------- decrypt ---------- */
    src = BIO_new_mem_buf(cipher_buf, (int)cipher_len);
    if (!TEST_ptr(src))
        goto end;
    if (!TEST_ptr(dec = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))   /* 0 → decrypt */
        goto end;
    BIO_push(dec, src);                     /* dec -> src */

    decrypted = OPENSSL_malloc(plaintext_len);
    if (!TEST_ptr(decrypted))
        goto end;

    /* read the decrypted data (may require a loop) */
    i = 0;
    while ((n = BIO_read(dec, decrypted + i, plaintext_len - i)) > 0)
        i += n;
    if (!TEST_int_eq(i, plaintext_len))
        goto end;

    /* compare with the original plaintext */
    if (!TEST_mem_eq(decrypted, plaintext_len, plaintext, plaintext_len))
        goto end;

    ret = 1;   /* success */

end:
    BIO_free_all(enc);      /* frees enc and the underlying mem BIO */
    BIO_free_all(dec);      /* frees dec and the underlying src BIO */
    OPENSSL_free(decrypted);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
