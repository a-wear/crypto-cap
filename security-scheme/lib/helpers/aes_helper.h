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

#ifndef __SECURITY_SCHEME_AES_HELPER_H_
#define __SECURITY_SCHEME_AES_HELPER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <assert.h>

#include <openssl/evp.h>

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
extern int aes_128_ecb_encrypt(const void *key, void *ciphertext, int *ciphertext_length, const void *plaintext, int plaintext_length);

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
extern int aes_128_ecb_decrypt(const void *key, void *plaintext, int *plaintext_length, const void *ciphertext, int ciphertext_length);

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
extern int aes_128_cbc_encrypt(const void *key, const void *iv, void *ciphertext, int *ciphertext_length, const void *plaintext, int plaintext_length);

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
extern int aes_128_cbc_decrypt(const void *key, const void *iv, void *plaintext, int *plaintext_length, const void *ciphertext, int ciphertext_length);

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
extern int aes_128_gcm_encrypt(const void *key, const void *iv, void *ciphertext, int *ciphertext_length, const void *plaintext, int plaintext_length, void *tag);

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
extern int aes_128_gcm_decrypt(const void *key, const void *iv, void *plaintext, int *plaintext_length, const void *ciphertext, int ciphertext_length, void *tag);

#ifdef __cplusplus
}
#endif

#endif /* __SECURITY_SCHEME_AES_HELPER_H_ */
