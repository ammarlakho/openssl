/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p6_tp1_s3_260827_130000.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test AES‑256‑CBC BIO encryption → decryption round‑trip */
    const unsigned char key[32] = {0};
    const unsigned char iv[16] = {0};
    const char plaintext[] = "OpenSSL test vector for AES‑256‑CBC BIO";
    const size_t plen = sizeof(plaintext) - 1;          /* exclude NUL */
    unsigned char outbuf[128];
    unsigned char *cipher = NULL;
    long clen = 0, readlen = 0;
    BIO *mem = NULL, *enc = NULL;
    BIO *mem2 = NULL, *dec = NULL;
    BUF_MEM *bptr = NULL;
    int ret = 0;
    int written, r;

    /* ---------- encryption side ---------- */
    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto end;
    if (!TEST_ptr(enc = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))          /* encrypt */
        goto end;
    BIO_push(enc, mem);

    written = BIO_write(enc, plaintext, (int)plen);
    if (!TEST_int_eq(written, (int)plen))
        goto end;
    if (!TEST_true(BIO_flush(enc)))                     /* final block */
        goto end;

    /* extract ciphertext from the memory BIO */
    if (!TEST_true(BIO_get_mem_ptr(mem, &bptr)))
        goto end;
    clen = bptr->length;
    if (!TEST_int_gt(clen, 0))
        goto end;
    if (!TEST_ptr(cipher = OPENSSL_malloc((size_t)clen)))
        goto end;
    memcpy(cipher, bptr->data, (size_t)clen);

    /* free encryption chain – ciphertext is now in our own buffer */
    BIO_free_all(enc);
    enc = NULL;
    mem = NULL;

    /* ---------- decryption side ---------- */
    if (!TEST_ptr(mem2 = BIO_new_mem_buf(cipher, (int)clen)))
        goto end;
    if (!TEST_ptr(dec = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))          /* decrypt */
        goto end;
    BIO_push(dec, mem2);

    /* read decrypted data */
    while ((r = BIO_read(dec, outbuf + readlen,
                        (int)(sizeof(outbuf) - readlen))) > 0) {
        readlen += r;
    }
    if (r < 0 && !BIO_should_retry(dec))
        goto end;   /* an error occurred */

    if (!TEST_int_eq((int)readlen, (int)plen))
        goto end;
    if (!TEST_mem_eq(outbuf, readlen, plaintext, plen))
        goto end;

    ret = 1;   /* all checks passed */

end:
    BIO_free_all(dec);   /* also frees mem2 */
    OPENSSL_free(cipher);
    return ret;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
