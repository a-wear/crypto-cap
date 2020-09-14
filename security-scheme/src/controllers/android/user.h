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

#ifndef __SECURITY_SCHEME_CONTROLLER_USER_H_
#define __SECURITY_SCHEME_CONTROLLER_USER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <string.h>
#include <assert.h>

#include <openssl/rand.h>
#include <openssl/evp.h>

#include "models/user.h"
#include "models/verifier.h"

#include "system.h"

#include "include/apdu.h"
#include "apdu/command.h"
#include "pcsc/reader.h"

/**
 * Gets the user identifier.
 *
 * @param reader the reader to be used
 * @param identifier the user identifier
 * @return 0 if success else -1
 */
extern int ue_get_user_identifier(reader_t reader, user_identifier_t *identifier);

/**
 * Sets the user identifier and private key using the specified reader.
 *
 * @param reader the reader to be used
 * @param identifier the user identifier
 * @param private_key the user private key
 * @return 0 if success else -1
 */
extern int ue_set_user_identifier_private_key(reader_t reader, user_identifier_t identifier, user_private_key_t private_key);

/**
 * Exchanges the identifier and the nonce between the user and the verifier using the specified reader.
 *
 * @param reader the reader to be used
 * @param identifier the user identifier to be received
 * @param ve_identifier the verifier identifier to be sent
 * @param nonce the user nonce to be received
 * @param ve_nonce the verifier nonce to be sent
 * @return 0 if success else -1
 */
extern int ue_exchange_identifier_nonce(reader_t reader, user_identifier_t *identifier, verifier_identifier_t ve_identifier, user_nonce_t *nonce, verifier_nonce_t ve_nonce);

/**
 * Computes the first stage of the user show using the specified reader.
 *
 * @param reader the reader to be used
 * @param parameters the system parameters
 * @param ue_identifier the user identifier
 * @param ve_identifier the verifier identifier
 * @param ue_nonce the user nonce
 * @param ve_nonce the verifier nonce
 * @param ue_private_key the user private key
 * @param ue_cipher_output the user cipher output
 * @return 0 if success else -1
 */
extern int ue_show_stage_1(reader_t reader, system_par_t *parameters, user_identifier_t ue_identifier, verifier_identifier_t ve_identifier, user_nonce_t ue_nonce, verifier_nonce_t ve_nonce,
                           user_private_key_t ue_private_key, user_cipher_output_t *ue_cipher_output);

/**
 * Computes the second stage of the user show and gets the session key using the specified reader.
 *
 * @param reader the reader to be used
 * @param parameters the system parameters
 * @param ue_identifier the user identifier
 * @param ve_identifier the verifier identifier
 * @param ue_nonce the user nonce
 * @param ve_nonce the verifier nonce
 * @param ue_keys the user keys
 * @param ve_cipher_output the verifier cipher output
 * @return 0 if success else -1
 */
extern int ue_show_stage_2(reader_t reader, system_par_t *parameters, user_identifier_t ue_identifier, verifier_identifier_t ve_identifier, user_nonce_t ue_nonce, verifier_nonce_t ve_nonce,
                           user_keys_t *ue_keys, verifier_cipher_output_t ve_cipher_output);

#ifdef __cplusplus
}
#endif

#endif /* __SECURITY_SCHEME_CONTROLLER_USER_H_ */
