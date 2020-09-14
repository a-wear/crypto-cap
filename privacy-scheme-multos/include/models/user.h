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

#ifndef __PRIVACY_SCHEME_MULTOS_MODEL_USER_H_
#define __PRIVACY_SCHEME_MULTOS_MODEL_USER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include "config/config.h"

#include "types.h"

typedef struct
{
    uint8_t buffer[USER_MAX_ID_LENGTH];
} user_identifier_t;

typedef struct
{
    elliptic_curve_point_t key_hat;
    uint8_t e[SHA_DIGEST_LENGTH];
    elliptic_curve_multiplier_t s;
    elliptic_curve_fr_t s_id;
} user_proof_of_key_t;

typedef struct
{
    elliptic_curve_point_t key_hat;
    elliptic_curve_point_t t;
    uint8_t nonce[NONCE_LENGTH];
} user_hash_data_t;

#ifdef __cplusplus
}
#endif

#endif /* __PRIVACY_SCHEME_MULTOS_MODEL_USER_H_ */
