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

#ifndef __SECURITY_SCHEME_CONTROLLER_VERIFIER_H_
#define __SECURITY_SCHEME_CONTROLLER_VERIFIER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <string.h>

#include <openssl/rand.h>

#include "models/user.h"
#include "models/verifier.h"

#include "system.h"

#include "helpers/aes_helper.h"

/**
 * Gets the verifier identifier.
 *
 * @param identifier the verifier identifier
 * @return 0 if success else -1
 */
extern int ve_get_verifier_identifier(verifier_identifier_t *identifier);

/**
 * Generates the verifier nonce.
 *
 * @param nonce the verifier nonce
 * @return 0 if success else -1
 */
extern int ve_generate_nonce(verifier_nonce_t *nonce);

/**
 * Computes the verification of the first stage of the user show.
 *
 * @param parameters the system parameters
 * @param ue_identifier the user identifier
 * @param ve_identifier the verifier identifier
 * @param ue_nonce the user nonce
 * @param ve_nonce the verifier nonce
 * @param ve_keys the verifier keys
 * @param ue_cipher_output the user cipher output
 * @param ve_cipher_output the verifier cipher output
 * @return 0 if success else -1
 */
extern int ve_verify(system_par_t *parameters, user_identifier_t ue_identifier, verifier_identifier_t ve_identifier, user_nonce_t ue_nonce, verifier_nonce_t ve_nonce,
                     verifier_keys_t *ve_keys, user_cipher_output_t ue_cipher_output, verifier_cipher_output_t *ve_cipher_output);

#ifdef __cplusplus
}
#endif

#endif /* __SECURITY_SCHEME_CONTROLLER_VERIFIER_H_ */
