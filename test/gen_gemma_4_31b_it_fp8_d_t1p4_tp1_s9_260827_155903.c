/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gemma_4_31b_it_fp8_d_t1p4_tp1_s9_260827_155903.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    BIO *fenc = NULL, *fdec = NULL, *bmem_out = NULL, *bmem_in = NULL, *chain = NULL;
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const char *plaintext = "The quick brown fox jumps over the lazy dog for BIO cipher test.";
    int pt_len = (int)strlen(plaintext);
    unsigned char decrypted[256];
    int read_len = 0;
    char *ct_ptr = NULL;

    /* Setup Encryption Chain: [CIPHER BIO] -> [MEMORY BIO] */
    bmem_out = BIO_new(BIO_s_mem());
    fenc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bmem_out) || !TEST_ptr(fenc)) {
        ok = 0;
        goto cleanup;
    }
    chain = BIO_push(fenc, bmem_out);
    if (!TEST_ptr(chain)) {
        ok = 0;
        goto cleanup;
    }

    if (!TEST_true(BIO_set_cipher(chain, EVP_aes_256_cbc(), key, iv, 1))) {
        ok = 0;
        goto cleanup;
    }

    if (!TEST_true(BIO_write(chain, plaintext, pt_len) == pt_len)) {
        ok = 0;
        goto cleanup;
    }

    /* Finalize encryption blocks */
    if (!TEST_true(BIO_ctrl(chain, BIO_CTRL_FLUSH, 0, NULL))) {
        ok = 0;
        goto cleanup;
    }

    /* Get ciphertext produced in memory BIO */
    long ct_len = BIO_get_mem_data(bmem_out, &ct_ptr);
    if (!TEST_true(ct_len > 0)) {
        ok = 0;
        goto cleanup;
    }

    /* Setup Decryption Chain: [CIPHER BIO] -> [MEMORY BIO containing CT] */
    bmem_in = BIO_new_mem_buf(ct_ptr, ct_len);
    fdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bmem_in) || !TEST_ptr(fdec)) {
        ok = 0;
        goto cleanup;
    }
    BIO *chain_dec = BIO_push(fdec, bmem_in);
    if (!TEST_ptr(chain_dec)) {
        ok = 0;
        goto cleanup;
    }

    if (!TEST_true(BIO_set_cipher(chain_dec, EVP_aes_256_cbc(), key, iv, 0))) {
        ok = 0;
        goto cleanup;
    }

    /* Read and decrypt until EOF */
    while ((read_len = BIO_read(chain_dec, (char *)(decrypted + (read_len)), 
                                (int)(sizeof(decrypted) - read_len))) > 0);
    
    /* Note: enc_read handles EVP_CipherFinal_ex internally when BIO_read(next) returns 0.
     * However, to be absolutely sure we get everything, we check total length. */
    
    /* read_len now contains total bytes decrypted if the while loop used addition. 
     * Let's correct the accumulator. */
    int total_dec = 0;
    int loop_ret = 0;
    /* Reset memory BIO for clean read */
    BIO_set_mem_offset(bmem_in, 0); 
    while ((loop_ret = BIO_read(chain_dec, (char *)(decrypted + total_dec), 
                                (int)(sizeof(decrypted) - total_dec))) > 0) {
        total_dec += loop_ret;
    }

    if (!TEST_true(total_dec == pt_len)) {
        ok = 0;
        goto cleanup;
    }

    if (!TEST_mem_eq((unsigned char *)plaintext, pt_len, decrypted, total_dec)) {
        ok = 0;
        goto cleanup;
    }

cleanup:
    if (chain) BIO_free_all(chain);
    if (fdec) { 
        /* If chain_dec was created, it replaces fdec in the chain handle */
        /* Since fdec was pushed, BIO_free_all on the chain is correct. 
         * But if chain_dec construction failed, we need it here. */
    }
    /* chain_dec logic requires care to avoid double free. 
       If chain_dec = BIO_push(fdec, bmem_in), then BIO_free_all(chain_dec) frees both. */
    if (fdec && !chain_dec) BIO_free(fdec); // Unlikely overlap with previous block
    if (bmem_in && !fdec) BIO_free(bmem_in); // Simplified: usually chain_dec exists

    /* In our flow, fdec was pushed into a chain (not stored as a separate member) */
    /* The most robust way given the local vars: */
    if (fdec && !chain_dec) BIO_free(fdec); 
    /* Wait, we didn't store chain_dec. Let's ensure the decryption chain is freed. */
    /* Adjusted logic: only one chain existed for encryption, one for decryption. */
    
    /* Decryption cleanup again to be sure */
    /* Because bmem_in and fdec are wrapped in the anonymous handle result of BIO_push */
    /* just use a dedicated pointer for chain_dec. */

    return ok;

*(Note: I noticed a logic flaw in the cleanup of `chain_dec` not being explicitly tracked in my cleanup list; however, in the actual replacement, I'll ensure `chain_dec` is assigned and freed for correctness.)*

**Revised Clean Replacement:**

    int ok = 1;
    BIO *fenc = NULL, *fdec = NULL, *bmem_out = NULL, *bmem_in = NULL, *chain_enc = NULL, *chain_dec = NULL;
    unsigned char key[32] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    unsigned char iv[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    const char *plaintext = "The quick brown fox jumps over the lazy dog.";
    int pt_len = (int)strlen(plaintext);
    unsigned char decrypted[256];
    int total_dec = 0;
    char *ct_ptr = NULL;

    bmem_out = BIO_new(BIO_s_mem());
    fenc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bmem_out) || !TEST_ptr(fenc)) { ok = 0; goto cleanup; }
    chain_enc = BIO_push(fenc, bmem_out);
    if (!TEST_ptr(chain_enc)) { ok = 0; goto cleanup; }

    if (!TEST_true(BIO_set_cipher(chain_enc, EVP_aes_256_cbc(), key, iv, 1))) { ok = 0; goto cleanup; }
    if (!TEST_true(BIO_write(chain_enc, plaintext, pt_len) == pt_len)) { ok = 0; goto cleanup; }
    if (!TEST_true(BIO_ctrl(chain_enc, BIO_CTRL_FLUSH, 0, NULL))) { ok = 0; goto cleanup; }

    long ct_len = BIO_get_mem_data(bmem_out, &ct_ptr);
    if (!TEST_true(ct_len > 0)) { ok = 0; goto cleanup; }

    bmem_in = BIO_new_mem_buf(ct_ptr, ct_len);
    fdec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(bmem_in) || !TEST_ptr(fdec)) { ok = 0; goto cleanup; }
    chain_dec = BIO_push(fdec, bmem_in);
    if (!TEST_ptr(chain_dec)) { ok = 0; goto cleanup; }

    if (!TEST_true(BIO_set_cipher(chain_dec, EVP_aes_256_cbc(), key, iv, 0))) { ok = 0; goto cleanup; }

    int read_ret;
    while ((read_ret = BIO_read(chain_dec, (char *)(decrypted + total_dec), 
                                (int)(sizeof(decrypted) - total_dec))) > 0) {
        total_dec += read_ret;
    }

    if (!TEST_true(total_dec == pt_len)) { ok = 0; goto cleanup; }
    if (!TEST_mem_eq((unsigned char *)plaintext, pt_len, decrypted, total_dec)) { ok = 0; goto cleanup; }

cleanup:
    if (chain_enc) BIO_free_all(chain_enc);
    if (chain_dec) BIO_free_all(chain_dec);
    return ok;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
