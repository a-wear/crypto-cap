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

#ifndef __SECURITY_SCHEME_MODEL_VERIFIER_H_
#define __SECURITY_SCHEME_MODEL_VERIFIER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#include "config/config.h"

typedef struct
{
    uint8_t buffer[VERIFIER_MAX_ID_LENGTH];
    size_t buffer_length;
} verifier_identifier_t;

typedef struct
{
    uint8_t sk[AES_BLOCK_SIZE]; // 128 bits
} verifier_private_key_t;

typedef struct
{
    uint8_t sk[AES_BLOCK_SIZE]; // 128 bits
} verifier_session_key_t;

typedef struct
{
    verifier_private_key_t private_key; // 128 bits
    verifier_session_key_t session_key; // 128 bits
} verifier_keys_t;

typedef struct
{
    uint8_t nonce[NONCE_LENGTH]; // 128 bits
} verifier_nonce_t;

typedef struct
{
    uint8_t verifier_identifier[AES_BLOCK_SIZE];
    uint8_t user_identifier[AES_BLOCK_SIZE];
    uint8_t verifier_nonce[AES_BLOCK_SIZE];
    uint8_t user_nonce[AES_BLOCK_SIZE];
    uint8_t session_key[AES_BLOCK_SIZE];
} verifier_cipher_data_t;

typedef struct
{
    // sizeof(verifier_cipher_data_t) = 5·AES_BLOCK_SIZE
    uint8_t cipher_output[5 * AES_BLOCK_SIZE];
} verifier_cipher_output_t;

#ifdef __cplusplus
}
#endif

#endif /* __SECURITY_SCHEME_MODEL_VERIFIER_H_ */
