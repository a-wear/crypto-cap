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

#ifndef __SECURITY_SCHEME_CONTROLLER_ISSUER_H_
#define __SECURITY_SCHEME_CONTROLLER_ISSUER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <assert.h>

#include <openssl/rand.h>
#include <openssl/evp.h>

#include "models/issuer.h"
#include "models/user.h"
#include "models/verifier.h"

#include "system.h"

#include "config/config.h"

/**
 * Generates the issuer master key.
 *
 * @param master_key the issuer master key
 * @return 0 if success else -1
 */
extern int ie_setup(issuer_master_key_t *master_key);

/**
 * Generates a unique secret key for the user and the verifier.
 *
 * @param parameters the system parameters
 * @param master_key the issuer master key
 * @param ue_identifier the user identifier
 * @param ve_identifier the verifier identifier
 * @param ue_private_key the user private key
 * @param ve_private_key the verifier private key
 * @return 0 if success else -1
 */
extern int ie_issue(system_par_t *parameters, issuer_master_key_t master_key, user_identifier_t ue_identifier, verifier_identifier_t ve_identifier, user_private_key_t *ue_private_key, verifier_private_key_t *ve_private_key);

#ifdef __cplusplus
}
#endif

#endif /* __SECURITY_SCHEME_CONTROLLER_ISSUER_H_ */
