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

#ifndef __SECURITY_SCHEME_APDU_H_
#define __SECURITY_SCHEME_APDU_H_

#ifdef __cplusplus
extern "C"
{
#endif

#define SW_LENGTH               2
#define COMMAND_HEADER_SIZE_T0  6
#define COMMAND_HEADER_SIZE_T1  10

#define MAX_APDU_LENGTH_T0      255
#define MAX_APDU_LENGTH_T1      65535

#define MAX_APDU_SEND_SIZE_T0   (MAX_APDU_LENGTH_T0 - COMMAND_HEADER_SIZE_T0)
#define MAX_APDU_RECV_SIZE_T0   (MAX_APDU_LENGTH_T0 - SW_LENGTH)

#define MAX_APDU_SEND_SIZE_T1   (MAX_APDU_LENGTH_T1 - COMMAND_HEADER_SIZE_T1)
#define MAX_APDU_RECV_SIZE_T1   (MAX_APDU_LENGTH_T1 - SW_LENGTH)

#define CLA_APPLICATION                                 0x80

#define INS_SET_USER_IDENTIFIER_ISSUER_SIGNATURE        0x10

#define INS_COMPUTE_PROOF_OF_KEY                        0x20

/**
 * APDU message to select the application on the smart card
 */
#if defined (PRIVACY_SCHEME_MULTOS)
static const uint8_t APDU_SCARD_SELECT_APPLICATION[] = {0x00, 0xA4, 0x04, 0x00, 0x04, 0xf0, 0x00, 0x00, 0x02, 0x00};
//                                                      CLA   INS   P1    P2    Lc    AID1  AID2  AID3  AID4  Le
#elif defined(PRIVACY_SCHEME_ANDROID)
static const uint8_t APDU_SCARD_SELECT_APPLICATION[] = {0x00, 0xA4, 0x04, 0x00, 0x07, 0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00};
//                                                      CLA   INS   P1    P2    Lc    AID1  AID2  AID3  AID4  AID5  AID6  AID7  Le
#endif

#ifdef __cplusplus
}
#endif

#endif /* __SECURITY_SCHEME_APDU_H_ */
