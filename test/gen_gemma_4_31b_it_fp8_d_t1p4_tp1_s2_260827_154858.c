/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p4_tp1_s2_260827_154858.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    int ok = 0;
    BIO *bmem = NULL, *bfilter = NULL;
    unsigned char *outbuf = NULL;
    int outlen = 0;
    
    const unsigned char key[32] = "01234567890123456789012345678901";
    const unsigned char iv[16] = "0123456789012345";
    const char *plaintext = "The quick brown fox jumps over the lazy dog. AES-256-CBC BIO test!";
    int plaintext_len = (int)strlen(plaintext) + 1;

    /* Encryption Phase */
    bmem = BIO_new(BIO_s_mem());
    if (!TEST_ptr(bmem))
        goto err;

    bfilter = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bfilter))
        goto err;

    if (!TEST_true(BIO_push(bfilter, bmem)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bfilter, EVP_aes_256_cbc(), key, iv, 1)))
        goto err;

    if (!TEST_true(BIO_write(bfilter, plaintext, plaintext_len) == plaintext_len))
        goto err;

    /* Flush ensures padding is processed and everything is written to the mem BIO */
    if (!TEST_true(BIO_ctrl(bfilter, BIO_CTRL_FLUSH, 0, NULL)))
        goto err;

    /* Transition: The bfilter (encrypt) is no longer needed, 
     * we only need the underlying bmem containing the ciphertext. */
    BIO_set_init(bfilter, 0); /* stop reading further */
    
    /* Now we wrap bmem in a decryption filter */
    /* Since we cannot easily pop in this context without risking memory, 
     * we simply rebuild the chain or use the memory BIO as the source.
     * Bmem is still attached to the old bfilter. To isolate bmem, 
     * we can use a new decryption filter and push bmem if shared, 
     * but it's safer to create a fresh memory BIO from the generated output. */
    
    char *ciphertext = NULL;
    long cipherlen = BIO_ctrl_pending(bmem);
    if (cipherlen <= 0)
        goto err;
    
    ciphertext = OPENSSL_malloc(cipherlen);
    if (!TEST_ptr(ciphertext))
        goto err;
    
    BIO_set_mem_offset(bmem, 0);
    if (!TEST_true(BIO_read(bmem, ciphertext, (int)cipherlen) == cipherlen))
        goto err;

    /* Decryption Phase */
    BIO *bdec = NULL;
    BIO *bmem_dec = NULL;

    bmem_dec = BIO_new_mem_buf(ciphertext, (int)cipherlen);
    if (!TEST_ptr(bmem_dec))
        goto err;

    bdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bdec))
        goto err;

    if (!TEST_true(BIO_push(bdec, bmem_dec)))
        goto err;

    if (!TEST_true(BIO_set_cipher(bdec, EVP_aes_256_cbc(), key, iv, 0)))
        goto err;

    outbuf = OPENSSL_malloc(plaintext_len + 32); /* enough space for block */
    if (!TEST_ptr(outbuf))
        goto err;

    int read_bytes = BIO_read(bdec, outbuf, plaintext_len);
    if (!TEST_true(read_bytes == plaintext_len))
        goto err;

    if (!TEST_mem_eq(plaintext, plaintext_len, outbuf, read_bytes))
        goto err;

    ok = 1;

err:
    if (ciphertext) OPENSSL_free(ciphertext);
    if (outbuf) OPENSSL_free(outbuf);
    if (bfilter) BIO_free_all(bfilter); /* this frees bmem too */
    if (bdec) BIO_free_all(bdec);      /* this frees bmem_dec */
    
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
