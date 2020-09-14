/**
 *
 *  Copyright (C) 2020  Raul Casanova Marques
 *
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "aes_helper.h"

/**
 * Encrypts data using AES-128, ECB mode (no-padding).
 *
 * @param key the key used to encrypt
 * @param ciphertext the output buffer where the ciphertext will be stored
 * @param ciphertext_length the length of the output buffer
 * @param plaintext the input buffer to be encrypted
 * @param plaintext_length the length of the input buffer
 * @return 0 if success else -1
 */
int aes_128_ecb_encrypt(const void *key, void *ciphertext, int *ciphertext_length, const void *plaintext, int plaintext_length)
{
    EVP_CIPHER_CTX *ctx;

    int length;
    int r;

    // create and initialise the context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }

    // initialize encrypt
    r = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    if (r != 1)
    {
        return -2;
    }

    // disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // obtain the ciphertext
    r = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length);
    if (r != 1)
    {
        return -3;
    }
    assert(length == *ciphertext_length); // no padding
    *ciphertext_length = length;

    // finalise the encryption
    r = EVP_EncryptFinal_ex(ctx, ciphertext, &length);
    if (r != 1)
    {
        return -4;
    }
    assert(length == 0); // no output expected, length must be 0

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

/**
 * Decrypts data using AES-128, ECB mode (no-padding).
 *
 * @param key the key used to decrypt
 * @param plaintext the output buffer where the plaintext will be stored
 * @param plaintext_length the length of the output buffer
 * @param ciphertext the input buffer to be decrypted
 * @param ciphertext_length the length of the input buffer
 * @return 0 if success else -1
 */
int aes_128_ecb_decrypt(const void *key, void *plaintext, int *plaintext_length, const void *ciphertext, int ciphertext_length)
{
    EVP_CIPHER_CTX *ctx;

    int length;
    int r;

    // create and initialise the context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }

    // initialize decrypt
    r = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    if (r != 1)
    {
        return -2;
    }

    // disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // obtain the plaintext
    r = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_length);
    if (r != 1)
    {
        return -3;
    }
    assert(length == *plaintext_length); // no padding
    *plaintext_length = length;

    // finalise the decryption
    r = EVP_DecryptFinal_ex(ctx, plaintext, &length);
    if (r != 1)
    {
        return -4;
    }
    assert(length == 0); // no output expected, length must be 0

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

/**
 * Encrypts data using AES-128, CBC mode (no-padding).
 *
 * @param key the key used to encrypt
 * @param iv the initialization vector
 * @param ciphertext the output buffer where the ciphertext will be stored
 * @param ciphertext_length the length of the output buffer
 * @param plaintext the input buffer to be encrypted
 * @param plaintext_length the length of the input buffer
 * @return 0 if success else -1
 */
int aes_128_cbc_encrypt(const void *key, const void *iv, void *ciphertext, int *ciphertext_length, const void *plaintext, int plaintext_length)
{
    EVP_CIPHER_CTX *ctx;

    int length;
    int r;

    // create and initialise the context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }

    // initialize encrypt
    r = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    if (r != 1)
    {
        return -2;
    }

    // disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // obtain the ciphertext
    r = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length);
    if (r != 1)
    {
        return -3;
    }
    assert(length == *ciphertext_length); // no padding
    *ciphertext_length = length;

    // finalise the encryption
    r = EVP_EncryptFinal_ex(ctx, ciphertext, &length);
    if (r != 1)
    {
        return -4;
    }
    assert(length == 0); // no output expected, length must be 0

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

/**
 * Decrypts data using AES-128, CBC mode (no-padding).
 *
 * @param key the key used to decrypt
 * @param iv the initialization vector
 * @param plaintext the output buffer where the plaintext will be stored
 * @param plaintext_length the length of the output buffer
 * @param ciphertext the input buffer to be decrypted
 * @param ciphertext_length the length of the input buffer
 * @return 0 if success else -1
 */
int aes_128_cbc_decrypt(const void *key, const void *iv, void *plaintext, int *plaintext_length, const void *ciphertext, int ciphertext_length)
{
    EVP_CIPHER_CTX *ctx;

    int length;
    int r;

    // create and initialise the context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }

    // initialize decrypt
    r = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    if (r != 1)
    {
        return -2;
    }

    // disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // obtain the plaintext
    r = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_length);
    if (r != 1)
    {
        return -3;
    }
    assert(length == *plaintext_length); // no padding
    *plaintext_length = length;

    // finalise the decryption
    r = EVP_DecryptFinal_ex(ctx, plaintext, &length);
    if (r != 1)
    {
        return -4;
    }
    assert(length == 0); // no output expected, length must be 0

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

/**
 * Encrypts data using AES-128, GCM mode (no-padding).
 *
 * @param key the key used to encrypt
 * @param iv the initialization vector
 * @param ciphertext the output buffer where the ciphertext will be stored
 * @param ciphertext_length the length of the output buffer
 * @param plaintext the input buffer to be encrypted
 * @param plaintext_length the length of the input buffer
 * @param tag the tag used during the encryption
 * @return 0 if success else -1
 */
int aes_128_gcm_encrypt(const void *key, const void *iv, void *ciphertext, int *ciphertext_length, const void *plaintext, int plaintext_length, void *tag)
{
    EVP_CIPHER_CTX *ctx;

    int length;
    int r;

    // create and initialise the context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }

    // initialize encrypt
    r = EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    if (r != 1)
    {
        return -2;
    }

    // disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // obtain the ciphertext
    r = EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_length);
    if (r != 1)
    {
        return -3;
    }
    assert(length == *ciphertext_length); // no padding
    *ciphertext_length = length;

    // finalise the encryption
    r = EVP_EncryptFinal_ex(ctx, ciphertext, &length);
    if (r != 1)
    {
        return -4;
    }
    assert(length == 0); // no output expected, length must be 0

    // get the tag
    r = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    if (r != 1)
    {
        return -5;
    }

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

/**
 * Decrypts data using AES-128, GCM mode (no-padding).
 *
 * @param key the key used to decrypt
 * @param iv the initialization vector
 * @param plaintext the output buffer where the plaintext will be stored
 * @param plaintext_length the length of the output buffer
 * @param ciphertext the input buffer to be decrypted
 * @param ciphertext_length the length of the input buffer
 * @param tag the tag used during the encryption
 * @return 0 if success else -1
 */
int aes_128_gcm_decrypt(const void *key, const void *iv, void *plaintext, int *plaintext_length, const void *ciphertext, int ciphertext_length, void *tag)
{
    EVP_CIPHER_CTX *ctx;

    int length;
    int r;

    // create and initialise the context
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
    {
        return -1;
    }

    // initialize decrypt
    r = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv);
    if (r != 1)
    {
        return -2;
    }

    // disable padding
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    // obtain the plaintext
    r = EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_length);
    if (r != 1)
    {
        return -3;
    }
    assert(length == *plaintext_length); // no padding
    *plaintext_length = length;

    // set expected tag value
    r = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    if (r != 1)
    {
        return -4;
    }

    // finalise the decryption
    r = EVP_DecryptFinal_ex(ctx, plaintext, &length);
    if (r != 1)
    {
        return -5;
    }
    assert(length == 0); // no output expected, length must be 0

    EVP_CIPHER_CTX_free(ctx);

    return 0;
}
