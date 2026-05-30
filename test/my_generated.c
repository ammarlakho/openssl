#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypto/evp/bio_enc.h"
#include "crypto/evp/aes_cbc.h"

#define AES_BLOCK_SIZE 16
#define KEY_LENGTH 16

int main() {
    unsigned char key[KEY_LENGTH], iv[AES_BLOCK_SIZE];
    EVP_CIPHER_CTX *cipher;
    unsigned char plaintext[1024], ciphertext[1024];
    int plaintext_len, ciphertext_len;

    // Initialize AES-CBC cipher
    if (!EVP_EncryptInit_ex(NULL, EVP_aes_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing AES-CBC cipher\n");
        return 1;
    }

    // Generate random plaintext
    plaintext_len = rand() % (50 * AES_BLOCK_SIZE);
    for (int i = 0; i < plaintext_len; i++) {
        plaintext[i] = rand() % 256;
    }
    plaintext[plaintext_len] = '\0';

    // Encrypt plaintext
    if (!EVP_EncryptUpdate(cipher, ciphertext, &ciphertext_len, plaintext, [K
plaintext_len)) {
        fprintf(stderr, "Error encrypting plaintext\n");
        return 1;
    }

    // Finalize encryption
    if (!EVP_CipherFinal_ex(cipher, ciphertext + ciphertext_len, NULL)) {
        fprintf(stderr, "Error finalizing encryption\n");
        return 1;
    }
    ciphertext_len += EVP_CIPHER_CTX_get_block_size(cipher);

    // Decrypt ciphertext
    if (!EVP_DecryptInit_ex(NULL, EVP_aes_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Error initializing AES-CBC cipher for decryption\n[12D[K
decryption\n");
        return 1;
    }

    unsigned char decrypted_text[1024];
    int decrypted_len;

    if (!EVP_DecryptUpdate(cipher, decrypted_text, &decrypted_len, cipherte[8D[K
ciphertext, ciphertext_len)) {
        fprintf(stderr, "Error decrypting ciphertext\n");
        return 1;
    }

    // Finalize decryption
    if (!EVP_CipherFinal_ex(cipher, decrypted_text + decrypted_len, NULL)) [K
{
        fprintf(stderr, "Error finalizing decryption\n");
        return 1;
    }
    decrypted_len += EVP_CIPHER_CTX_get_block_size(cipher);

    // Output plaintext and decrypted text
    printf("Plaintext: %s\n", plaintext);
    printf("Decrypted Text: %s\n", decrypted_text);

    // Clean up
    EVP_CIPHER_CTX_free(cipher);

    return 0;
}

