/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p8_tp0p95_fp0p3_s2_260827_002715.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
    /* Test AES‑256‑CBC encryption/decryption using the BIO_f_cipher filter.
     * The ciphertext produced by the BIO chain is compared against a reference
     * ciphertext generated with the EVP API, then the ciphertext is fed back
     * through a decrypting BIO to verify that the original plaintext is
     * recovered. */
    const unsigned char key[32] = { 0 };
    const unsigned char iv[16]  = { 0 };
    const char plaintext[] = "OpenSSL BIO cipher test data";
    const int pt_len = (int)strlen(plaintext);
    unsigned char ref_ct[256];
    unsigned char ref_pt[256];
    int ref_ct_len = 0, ref_tmp = 0;
    int ret = 0;

    /* -----------------------------------------------------------------
     * 1. Produce reference ciphertext using the EVP API.
     * ----------------------------------------------------------------- */
    EVP_CIPHER_CTX *evp_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(evp_ctx))
        goto end;
    if (!TEST_int_eq(EVP_EncryptInit_ex(evp_ctx, EVP_aes_256_cbc(),
                                         NULL, key, iv), 1))
        goto end;
    if (!TEST_int_eq(EVP_EncryptUpdate(evp_ctx,
                                         ref_ct, &ref_tmp,
                                         (const unsigned char *)plaintext,
                                         pt_len), 1))
        goto end;
    ref_ct_len = ref_tmp;
    if (!TEST_int_eq(EVP_EncryptFinal_ex(evp_ctx,
                                         ref_ct + ref_ct_len, &ref_tmp), 1))
        goto end;
    ref_ct_len += ref_tmp;
    EVP_CIPHER_CTX_free(evp_ctx);
    evp_ctx = NULL;

    /* -----------------------------------------------------------------
     * 2. Encrypt using BIO_f_cipher and compare with reference ciphertext.
     * ----------------------------------------------------------------- */
    BIO *mem_enc = BIO_new(BIO_s_mem());
    BIO *bio_enc = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(mem_enc) || !TEST_ptr(bio_enc))
        goto end;
    if (!TEST_int_eq(BIO_set_cipher(bio_enc,
                                    EVP_aes_256_cbc(),
                                    key, iv, 1), 1))
        goto end;
    /* Chain: bio_enc (top) -> mem_enc (bottom) */
    BIO_push(bio_enc, mem_enc);

    if (!TEST_int_eq(BIO_write(bio_enc, plaintext, pt_len), pt_len))
        goto end;
    if (!TEST_int_eq(BIO_flush(bio_enc), 1))
        goto end;

    /* Retrieve ciphertext from the memory BIO */
    char *enc_data = NULL;
    long enc_len = BIO_get_mem_data(mem_enc, &enc_data);
    if (!TEST_int_eq((int)enc_len, ref_ct_len))
        goto end;
    if (!TEST_mem_eq(enc_data, (size_t)enc_len,
                     ref_ct, (size_t)ref_ct_len))
        goto end;

    /* Verify the cipher status flag is still OK */
    if (!TEST_int_eq(BIO_ctrl(bio_enc, BIO_C_GET_CIPHER_STATUS, 0, NULL), 1))
        goto end;

    /* Clean up the encryption chain */
    BIO_free_all(bio_enc); /* also frees mem_enc */

    /* -----------------------------------------------------------------
     * 3. Decrypt the ciphertext using BIO_f_cipher and verify plaintext.
     * ----------------------------------------------------------------- */
    BIO *mem_dec_src = BIO_new_mem_buf(enc_data, (int)enc_len);
    BIO *bio_dec = BIO_new(BIO_f_cipher());
    if (!TEST_ptr(mem_dec_src) || !TEST_ptr(bio_dec))
        goto end;
    if (!TEST_int_eq(BIO_set_cipher(bio_dec,
                                    EVP_aes_256_cbc(),
                                    key, iv, 0), 1))
        goto end;
    BIO_push(bio_dec, mem_dec_src);

    /* Read all decrypted bytes */
    unsigned char out_buf[256];
    int out_len = 0, r;
    while ((r = BIO_read(bio_dec, out_buf + out_len,
                         sizeof(out_buf) - out_len)) > 0) {
        out_len += r;
        if (out_len >= (int)sizeof(out_buf))
            break;
    }
    if (!TEST_int_ge(out_len, pt_len))
        goto end;
    if (!TEST_mem_eq(out_buf, (size_t)pt_len,
                     plaintext, (size_t)pt_len))
        goto end;

    ret = 1; /* success */

end:
    if (evp_ctx)
        EVP_CIPHER_CTX_free(evp_ctx);
    /* BIO_free_all safely handles NULL */
    BIO_free_all(bio_enc);
    BIO_free_all(bio_dec);
    return ret;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
