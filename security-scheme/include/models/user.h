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

#ifndef __SECURITY_SCHEME_MODEL_USER_H_
#define __SECURITY_SCHEME_MODEL_USER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <stdint.h>

#include "config/config.h"

typedef struct
{
    uint8_t buffer[USER_MAX_ID_LENGTH];
    size_t buffer_length;
} user_identifier_t;

typedef struct
{
    uint8_t sk[AES_BLOCK_SIZE]; // 128 bits
} user_private_key_t;

typedef struct
{
    uint8_t sk[AES_BLOCK_SIZE]; // 128 bits
} user_session_key_t;

typedef struct
{
    user_private_key_t private_key; // 128 bits
    user_session_key_t session_key; // 128 bits
} user_keys_t;

typedef struct
{
    uint8_t nonce[NONCE_LENGTH]; // 128 bits
} user_nonce_t;

typedef struct
{
    uint8_t user_identifier[AES_BLOCK_SIZE];
    uint8_t verifier_identifier[AES_BLOCK_SIZE];
    uint8_t user_nonce[AES_BLOCK_SIZE];
    uint8_t verifier_nonce[AES_BLOCK_SIZE];
} user_cipher_data_t;

typedef struct
{
    // sizeof(user_cipher_data_t) = 4·AES_BLOCK_SIZE
    uint8_t cipher_output[4 * AES_BLOCK_SIZE];
} user_cipher_output_t;

#ifdef __cplusplus
}
#endif

#endif /* __SECURITY_SCHEME_MODEL_USER_H_ */
