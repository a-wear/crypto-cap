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

#ifndef __SECURITY_SCHEME_CONFIG_H_
#define __SECURITY_SCHEME_CONFIG_H_

#ifdef __cplusplus
extern "C"
{
#endif

/*
 * AES config
 */
#define AES_BLOCK_SIZE  16 // 128 bits
#define AES_IV_LENGTH   16 // 128 bits

#define AES_GCM_IV_LENGTH   12 // 96 bits
#define AES_GCM_TAG_LENGTH  16 // 128 bits

/*
 * Length of nonce
 */
#define NONCE_LENGTH 16

/*
 * Maximum length of user id
 */
#define USER_MAX_ID_LENGTH 16

/*
 * Maximum length of verifier id
 */
#define VERIFIER_MAX_ID_LENGTH 16

#ifdef __cplusplus
}
#endif

#endif /* __SECURITY_SCHEME_CONFIG_H_ */
