/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p2_tp1_s9_260827_154515.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    BIO *b_mem = NULL, *b_enc = NULL, *b_dec = NULL;
    unsigned char key[32] = "01234567890123456789012345678901";
    unsigned char iv[16] = "0123456789012345";
    const char *plaintext = "This is a test for the BIO cipher using AES-256-CBC.";
    unsigned char out_buf[256];
    int pl_len = (int)strlen(plaintext) + 1;
    int read_len = 0;

    /* Create memory BIO as the sink/source */
    if (!TEST_ptr(b_mem = BIO_new(BIO_s_mem())))
        return 0;

    /* Set up Encryption Chain: BIO_f_cipher -> BIO_s_mem */
    if (!TEST_ptr(b_enc = BIO_new(BIO_f_cipher()))) {
        BIO_free(b_mem);
        return 0;
    }
    if (!TEST_true(BIO_push(b_enc, b_mem))) {
        BIO_free(b_enc); // This frees b_mem too
        return 0;
    }

    if (!TEST_true(BIO_set_cipher(b_enc, EVP_aes_256_cbc(), key, iv, 1))) {
        BIO_free(b_enc);
        return 0;
    }

    /* Write plaintext to trigger encryption */
    if (!TEST_true(BIO_write(b_enc, plaintext, pl_len) == pl_len)) {
        BIO_free(b_enc);
        return 0;
    }

    /* Flush the cipher BIO to process the final block and padding */
    if (!TEST_true(BIO_ctrl(b_enc, BIO_CTRL_FLUSH, 0, NULL))) {
        BIO_free(b_enc);
        return 0;
    }

    /* 
     * Now b_mem contains the ciphertext. 
     * To decrypt, we push a new cipher BIO on top of b_mem.
     * Since b_enc already owns b_mem, we create a new decryption 
     * BIO and re-use the underlying memory BIO.
     * 
     * Correct approach here for round-trip test:
     * Get the memory BIO back or create a new chain from the encrypted data.
     */
    
    /* Extract the pointer to the memory BIO from the head of the chain */
    BIO *bottom = b_enc;
    while (BIO_next(bottom) != NULL) {
        bottom = BIO_next(bottom);
    }
    
    /* Reset memory BIO pointer to the start for reading */
    if (!TEST_true(BIO_reset(bottom))) {
        BIO_free(b_enc);
        return 0;
    }

    /* Setup Decryption Chain: BIO_f_cipher -> BIO_s_mem (bottom) */
    if (!TEST_ptr(b_dec = BIO_new(BIO_f_cipher()))) {
        BIO_free(b_enc);
        return 0;
    }
    
    /* Use the memory bio we already have */
    if (!TEST_true(BIO_push(b_dec, bottom))) {
        BIO_free(b_dec);
        BIO_free(b_enc);
        return 0;
    }
    
    /* Set Decryption mode */
    if (!TEST_true(BIO_set_cipher(b_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        BIO_free(b_dec);
        BIO_free(b_enc);
        return 0;
    }

    /* Read back the plaintext */
    read_len = BIO_read(b_dec, (char *)out_buf, sizeof(out_buf));
    if (read_len <= 0) {
        BIO_free(b_dec);
        BIO_free(b_enc);
        return 0;
    }

    /* We must flush the dec BIO to handle the final block/padding */
    int final_len = BIO_read(b_dec, (char *)out_buf + read_len, sizeof(out_buf) - read_len);
    if (final_len > 0) {
        read_len += final_len;
    }

    /* Clean up first to avoid double-freeing 'bottom' */
    /* b_enc owns b_mem, but b_dec was pushed onto it too. 
       Actually, BIO_push makes b_dec the head. 
       Wait, b_enc was the head, then we found 'bottom'.
       We can't push 'bottom' into 'b_dec' while it's still in 'b_enc' chain 
       without calling BIO_set_next(b_enc, NULL). */
    
    /* Let's fix the ownership: disconnect bottom from b_enc before pushing to b_dec */
    /* Since this is a test, we can safely free only the heads and carefully 
       manage the chain. But simple way: free(b_dec) as it's the head of its own chain 
       that includes bottom. */

    int result = TEST_mem_eq(plaintext, pl_len, out_buf, read_len);
    
    /* 
     * Cleaning up: 
     * b_dec currently owns the chain leading to bottom.
     * b_enc was the old head and still thinks it owns bottom.
     * To avoid double free of bottom:
     */
    BIO_set_next(b_enc, NULL); 
    BIO_free(b_enc); 
    BIO_free(b_dec);

    return result;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
