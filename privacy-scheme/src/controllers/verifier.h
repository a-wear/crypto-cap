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

#ifndef __PRIVACY_SCHEME_CONTROLLER_VERIFIER_H_
#define __PRIVACY_SCHEME_CONTROLLER_VERIFIER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stddef.h>
#include <string.h>

#include <mcl/bn_c256.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "models/issuer.h"
#include "models/user.h"
#include "system.h"

#include "config/config.h"

#include "helpers/epoch_helper.h"
#include "helpers/hash_helper.h"
#include "helpers/mcl_helper.h"

/**
 * Generates a nonce to be used in the proof of key.
 *
 * @param nonce the nonce to be generated
 * @param nonce_length the length of the nonce
 * @return 0 if success else -1
 */
extern int ve_generate_nonce(void *nonce, size_t nonce_length);

/**
 * Verifies the proof of key of the user keys.
 *
 * @param sys_parameters the system parameters
 * @param ie_keys the issuer keys
 * @param nonce the nonce generated by the verifier
 * @param nonce_length the length of the nonce
 * @param ue_proof_of_key the proof of key computed by the user
 * @return 0 if success else -1
 */
extern int ve_verify_proof_of_key(system_par_t sys_parameters, issuer_keys_t ie_keys, const void *nonce, size_t nonce_length, user_proof_of_key_t ue_proof_of_key);

#ifdef __cplusplus
}
#endif

#endif /* __PRIVACY_SCHEME_CONTROLLER_VERIFIER_H_ */
