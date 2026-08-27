/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s2_260827_132413.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test encrypt‑then‑decrypt using the cipher BIO (AES‑256‑CBC). */
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
        "The quick brown fox jumps over the lazy dog";
    const size_t plaintext_len = sizeof(plaintext) - 1; /* no NUL */
    unsigned char outbuf[256];
    BIO *mem = NULL, *enc = NULL, *dec = NULL, *src = NULL;
    char *cipherdata = NULL;
    long cipherlen = 0;
    int outlen = 0, r, total = 0;
    int ok = 0; /* final result */

    /* ------- Encryption side ------- */
    mem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(mem))
        goto end;

    enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(enc))
        goto end;

    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                               key, iv, 1)))   /* encrypt */
        goto end;

    enc = BIO_push(enc, mem);    /* enc -> mem */

    r = BIO_write(enc, plaintext, (int)plaintext_len);
    if (!TEST_int_ge(r, plaintext_len))
        goto end;               /* should write whole plaintext */

    if (!TEST_true(BIO_flush(enc)))   /* push final block */
        goto end;

    cipherlen = BIO_get_mem_data(mem, &cipherdata);
    if (!TEST_long_gt(cipherlen, 0))
        goto end;

    /* ------- Decryption side ------- */
    src = BIO_new_mem_buf(cipherdata, (int)cipherlen);
    if (!TEST_ptr(src))
        goto end;

    dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(dec))
        goto end;

    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                               key, iv, 0)))   /* decrypt */
        goto end;

    dec = BIO_push(dec, src);    /* dec -> src */

    /* Read all decrypted data */
    while ((outlen = BIO_read(dec, outbuf + total,
                             (int)(sizeof(outbuf) - total))) > 0) {
        total += outlen;
        if (total >= (int)sizeof(outbuf))
            break;  /* avoid overflow – test data is small */
    }
    if (!TEST_int_ge(outlen, 0))  /* outlen == 0 means EOF, <0 is error */
        goto end;

    /* Verify that decrypted bytes match the original plaintext */
    if (!TEST_mem_eq(outbuf, total, plaintext, plaintext_len))
        goto end;

    ok = 1;   /* all checks passed */

end:
    /* Clean up all BIOs – free the top of each chain */
    BIO_free_all(enc);   /* also frees mem */
    BIO_free_all(dec);   /* also frees src */
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
