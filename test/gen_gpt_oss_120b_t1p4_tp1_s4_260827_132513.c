/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Skeleton for: gen_gpt_oss_120b_t1p4_tp1_s4_260827_132513.c — fill ONLY BEGIN_LLM_REPLACE .. END_LLM_REPLACE (past LLM).
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

#include "testutil.h"

static int test_bio_enc_generated(void)
{
    /* BEGIN_LLM_REPLACE */
        /* Encrypt a known plaintext with AES‑256‑CBC using a BIO filter and
         * then decrypt it again with a second BIO chain.  Verify that the
         * decrypted output matches the original plaintext. */
        const unsigned char key[32] = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
            0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f
        };
        const unsigned char iv[16] = {
            0xa0,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,
            0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf
        };
        const unsigned char plaintext[] =
            "OpenSSL BIO cipher round‑trip test data";
        const int plen = (int)sizeof(plaintext) - 1; /* ignore NUL */

        /*-------------------- Encryption side --------------------*/
        BIO *mem_enc = BIO_new(BIO_s_mem());
        if (!TEST_ptr(mem_enc))
            return 0;

        BIO *cipher_enc = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_enc)) {
            BIO_free(mem_enc);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(cipher_enc,
                                      EVP_aes_256_cbc(),
                                      key, iv, 1))) {
            BIO_free_all(cipher_enc);
            BIO_free(mem_enc);
            return 0;
        }

        /* Chain the cipher filter on top of the memory BIO. */
        BIO *enc_chain = BIO_push(cipher_enc, mem_enc);

        if (!TEST_true(BIO_write(enc_chain, plaintext, plen) == plen)) {
            BIO_free_all(enc_chain);
            return 0;
        }

        if (!TEST_true(BIO_flush(enc_chain))) {
            BIO_free_all(enc_chain);
            return 0;
        }

        /* Obtain the ciphertext from the memory BIO. */
        BUF_MEM *bptr = NULL;
        if (!TEST_true(BIO_get_mem_ptr(mem_enc, &bptr))) {
            BIO_free_all(enc_chain);
            return 0;
        }

        if (!TEST_true(bptr != NULL && bptr->length > 0)) {
            BIO_free_all(enc_chain);
            return 0;
        }

        /* Copy the ciphertext out before freeing the original BIOs. */
        unsigned char *ciphertext =
            OPENSSL_memdup((unsigned char *)bptr->data, bptr->length);
        if (!TEST_ptr(ciphertext)) {
            BIO_free_all(enc_chain);
            return 0;
        }

        BIO_free_all(enc_chain); /* frees both cipher & memory BIOs */

        /*-------------------- Decryption side --------------------*/
        BIO *mem_dec = BIO_new_mem_buf(ciphertext, (int)bptr->length);
        if (!TEST_ptr(mem_dec)) {
            OPENSSL_free(ciphertext);
            return 0;
        }

        BIO *cipher_dec = BIO_new(BIO_f_cipher());
        if (!TEST_ptr(cipher_dec)) {
            BIO_free(mem_dec);
            OPENSSL_free(ciphertext);
            return 0;
        }

        if (!TEST_true(BIO_set_cipher(cipher_dec,
                                      EVP_aes_256_cbc(),
                                      key, iv, 0))) {
            BIO_free_all(cipher_dec);
            BIO_free(mem_dec);
            OPENSSL_free(ciphertext);
            return 0;
        }

        BIO *dec_chain = BIO_push(cipher_dec, mem_dec);

        unsigned char outbuf[256];
        int outlen = BIO_read(dec_chain, outbuf, sizeof(outbuf));
        if (!TEST_true(outlen > 0)) {
            BIO_free_all(dec_chain);
            OPENSSL_free(ciphertext);
            return 0;
        }

        if (!TEST_true(outlen == plen)) {
            BIO_free_all(dec_chain);
            OPENSSL_free(ciphertext);
            return 0;
        }

        if (!TEST_mem_eq(outbuf, outlen, plaintext, plen)) {
            BIO_free_all(dec_chain);
            OPENSSL_free(ciphertext);
            return 0;
        }

        BIO_free_all(dec_chain);
        OPENSSL_free(ciphertext);
        return 1;
    /* END_LLM_REPLACE */
}

int setup_tests(void)
{
    ADD_TEST(test_bio_enc_generated);
    return 1;
}
