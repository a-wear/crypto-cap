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

#ifndef __PRIVACY_SCHEME_CONTROLLER_ISSUER_H_
#define __PRIVACY_SCHEME_CONTROLLER_ISSUER_H_

#ifdef __cplusplus
extern "C"
{
#endif

#include <string.h>

#include "models/issuer.h"
#include "models/user.h"

#include "helpers/epoch_helper.h"
#include "helpers/mcl_helper.h"

#include "system.h"

/**
 * Generates the issuer keys.
 *
 * @param keys the issuer keys
 * @return 0 if success else -1
 */
extern int ie_setup(issuer_keys_t *keys);

/**
 * Computes the signature of the user key and key prime using the private keys.
 *
 * @param sys_parameters the system parameters
 * @param keys the issuer keys
 * @param ue_identifier the user identifier
 * @param signature the signature of the user keys
 * @return 0 if success else -1
 */
extern int ie_issue(system_par_t sys_parameters, issuer_keys_t keys, user_identifier_t ue_identifier, issuer_signature_t *signature);

#ifdef __cplusplus
}
#endif

#endif /* __PRIVACY_SCHEME_CONTROLLER_ISSUER_H_ */
