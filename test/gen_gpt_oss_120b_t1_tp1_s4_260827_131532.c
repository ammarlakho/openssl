/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1_tp1_s4_260827_131532.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* test vector: zero key/IV, known plaintext */
    static const unsigned char key[32] = { 0 };
    static const unsigned char iv[16]  = { 0 };
    static const unsigned char plaintext[] =
        "The quick brown fox jumps over the lazy dog";
    const size_t plen = sizeof(plaintext) - 1; /* no trailing NUL */
    unsigned char outbuf[128];
    char *enc_data = NULL;
    long enc_len = 0;
    int i, total = 0;
    BIO *bmem = NULL, *bcipher = NULL;
    BIO *bmem_in = NULL, *bdec = NULL;
    int ok = 0;

    /* ---------- encrypt ---------- */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        goto end;

    bcipher = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bcipher))
        goto end;

    if (!TEST_true(BIO_set_cipher(bcipher,
                                 EVP_aes_256_cbc(),
                                 key, iv, 1)))          /* encrypt */
        goto end;

    /* chain: cipher writes into the memory BIO */
    BIO_push(bcipher, bmem);

    if (!TEST_int_gt(BIO_write(bcipher,
                              (const char *)plaintext,
                              (int)plen), 0))
        goto end;

    if (!TEST_true(BIO_flush(bcipher)))
        goto end;

    /* obtain ciphertext from the memory BIO */
    enc_len = BIO_get_mem_data(bmem, &enc_data);
    if (!TEST_true(enc_len > 0))
        goto end;

    /* ciphertext length must be a multiple of the block size (16) */
    if (!TEST_int_eq((int)(enc_len % 16), 0))
        goto end;

    /* ---------- decrypt ---------- */
    bmem_in = BIO_new_mem_buf(enc_data, (int)enc_len);
    if (!TEST_ptr(bmem_in))
        goto end;

    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec))
        goto end;

    if (!TEST_true(BIO_set_cipher(bdec,
                                 EVP_aes_256_cbc(),
                                 key, iv, 0)))          /* decrypt */
        goto end;

    BIO_push(bdec, bmem_in);

    /* read all decrypted bytes */
    total = 0;
    while ((i = BIO_read(bdec,
                        outbuf + total,
                        (int)sizeof(outbuf) - total)) > 0) {
        total += i;
        if (total >= (int)sizeof(outbuf))
            break; /* safety */
    }

    if (!TEST_int_eq(total, (int)plen))
        goto end;

    if (!TEST_mem_eq(outbuf, total, plaintext, plen))
        goto end;

    ok = 1;                     /* success */

end:
    BIO_free_all(bcipher);
    BIO_free_all(bmem);
    BIO_free_all(bdec);
    BIO_free_all(bmem_in);
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
