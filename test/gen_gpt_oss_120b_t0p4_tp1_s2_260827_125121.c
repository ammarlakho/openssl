/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p4_tp1_s2_260827_125121.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    const unsigned char key[32] = {0};
    const unsigned char iv[16] = {0};
    const char *msg = "OpenSSL BIO cipher test data";
    int msglen = (int)strlen(msg);
    BIO *enc = NULL, *mem = NULL;
    BUF_MEM *bptr = NULL;
    unsigned char *cipher = NULL;
    int cipherlen = 0;
    BIO *dec = NULL, *mem_in = NULL;
    unsigned char outbuf[256];
    int outlen = 0;
    int ok = 0;               /* return value: 1 on success, 0 on failure */

    /* ---------- Encryption ---------- */
    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto end;
    if (!TEST_ptr(enc = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1)))          /* encrypt */
        goto end;
    BIO_push(enc, mem);

    if (!TEST_int_eq(BIO_write(enc, msg, msglen), msglen))
        goto end;
    if (!TEST_true(BIO_flush(enc)))               /* ensure final block is written */
        goto end;

    /* Retrieve ciphertext from the memory BIO */
    if (!TEST_true(BIO_get_mem_ptr(mem, &bptr)))
        goto end;
    if (!TEST_int_gt(bptr->length, 0))
        goto end;

    cipherlen = bptr->length;
    cipher = OPENSSL_malloc(cipherlen);
    if (!TEST_ptr(cipher))
        goto end;
    memcpy(cipher, bptr->data, cipherlen);

    /* Clean up the encryption chain before decryption */
    BIO_free_all(enc);   /* also frees mem */
    enc = mem = NULL;    /* avoid double free */

    /* ---------- Decryption ---------- */
    if (!TEST_ptr(mem_in = BIO_new_mem_buf(cipher, cipherlen)))
        goto end;
    if (!TEST_ptr(dec = BIO_new(BIO_f_cipher())))
        goto end;
    if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                 key, iv, 0)))          /* decrypt */
        goto end;
    BIO_push(dec, mem_in);

    outlen = BIO_read(dec, outbuf, sizeof(outbuf));
    if (!TEST_int_gt(outlen, 0))
        goto end;
    if (!TEST_mem_eq(outbuf, outlen, msg, msglen))
        goto end;

    /* Verify that the cipher reported success */
    if (!TEST_long_eq(BIO_ctrl(dec, BIO_C_GET_CIPHER_STATUS, 0, NULL), 1))
        goto end;

    ok = 1;   /* all checks passed */

end:
    /* Release any resources that may still be allocated */
    BIO_free_all(enc);
    BIO_free_all(mem);
    BIO_free_all(dec);
    BIO_free_all(mem_in);
    OPENSSL_free(cipher);
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
