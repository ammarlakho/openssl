/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t0p2_tp1_s1_260827_123833.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
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
    /* Test AES‑256‑CBC BIO encryption/decryption round‑trip */
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
    const char *plaintext = "The quick brown fox jumps over the lazy dog";
    size_t pt_len = strlen(plaintext);
    int ok = 1;

    /* ---------- Encryption ---------- */
    BIO *mem_enc = BIO_new(BIO_s_mem());
    BIO *enc = BIO_new(BIO_f_cipher());

    if (!TEST_ptr(mem_enc) || !TEST_ptr(enc))
        return 0;

    if (!TEST_true(BIO_set_cipher(enc, EVP_aes_256_cbc(),
                                 key, iv, 1))) {
        ok = 0;
        goto cleanup_enc;
    }

    BIO_push(enc, mem_enc);               /* enc -> mem_enc */

    /* Write the whole plaintext, looping if BIO_write returns short */
    {
        size_t written = 0;
        while (written < pt_len) {
            int w = BIO_write(enc,
                              plaintext + written,
                              (int)(pt_len - written));
            if (!TEST_int_gt(w, 0)) {
                ok = 0;
                goto cleanup_enc;
            }
            written += w;
        }
    }

    if (!TEST_true(BIO_flush(enc))) {
        ok = 0;
        goto cleanup_enc;
    }

    /* Extract ciphertext from the memory BIO */
    BUF_MEM *bptr = NULL;
    if (!TEST_true(BIO_get_mem_ptr(mem_enc, &bptr))) {
        ok = 0;
        goto cleanup_enc;
    }
    unsigned char *ciphertext = OPENSSL_malloc(bptr->length);
    if (!TEST_ptr(ciphertext)) {
        ok = 0;
        goto cleanup_enc;
    }
    memcpy(ciphertext, bptr->data, bptr->length);
    size_t ct_len = bptr->length;

    /* ---------- Decryption ---------- */
    {
        BIO *mem_dec = BIO_new_mem_buf(ciphertext, (int)ct_len);
        BIO *dec = BIO_new(BIO_f_cipher());

        if (!TEST_ptr(mem_dec) || !TEST_ptr(dec)) {
            ok = 0;
            OPENSSL_free(ciphertext);
            goto cleanup_enc;
        }

        if (!TEST_true(BIO_set_cipher(dec, EVP_aes_256_cbc(),
                                     key, iv, 0))) {
            ok = 0;
            BIO_free_all(mem_dec);
            BIO_free(dec);
            OPENSSL_free(ciphertext);
            goto cleanup_enc;
        }

        BIO_push(dec, mem_dec);          /* dec -> mem_dec */

        /* Read decrypted data */
        unsigned char *outbuf = OPENSSL_malloc(ct_len);
        if (!TEST_ptr(outbuf)) {
            ok = 0;
            BIO_free_all(dec);
            OPENSSL_free(ciphertext);
            goto cleanup_enc;
        }

        size_t total_read = 0;
        for (;;) {
            int r = BIO_read(dec, outbuf + total_read,
                             (int)(ct_len - total_read));
            if (r > 0) {
                total_read += r;
                continue;
            }
            if (r == 0)      /* EOF */
                break;
            /* r < 0 : error / retry */
            if (!BIO_should_retry(dec)) {
                ok = 0;
                break;
            }
        }

        if (ok) {
            ok = TEST_int_eq((int)total_read, (int)pt_len) &&
                 TEST_mem_eq(outbuf, (int)pt_len,
                             plaintext, (int)pt_len);
        }

        OPENSSL_free(outbuf);
        BIO_free_all(dec);
        OPENSSL_free(ciphertext);
    }

cleanup_enc:
    BIO_free_all(enc);   /* also frees mem_enc */
    return ok;
}
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
