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

#ifndef __SECURITY_SCHEME_APDU_COMMAND_H_
#define __SECURITY_SCHEME_APDU_COMMAND_H_

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef NDEBUG
# include <stdio.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "apdu.h"

/**
 * ISO/IEC 7816-4:2005(E)
 *
 * A Case 1 command could be one that resets an application counter.
 * A Case 2 command might be one that reads data from the card.
 * A Case 3 command could be one that only writes data to the chip.
 * A Case 4 command might decrypt the incoming command data and return the value in plain text.
 */
typedef enum
{
    CASE1,  // As in short length, this case is not affected.
    CASE2S, // The legacy Case 2. LE has a value of 1 to 255.
    CASE2E, // The extended version of Case 2S, where LE is greater than 255.
    CASE3S, // The legacy Case 3. LC is less than 256 bytes of data, and LE is zero.
    CASE3E, // The extended version of Case 3, where LC is greater than 255, and LE is zero.
    CASE4S, // The legacy Case 4. LC and LE are less than 256 bytes of data.
    CASE4E  // The extended version of Case 4. LC or LE are greater than 256 bytes of data.
} apdu_iso_case_t;

/**
 * Builds a valid APDU command to transmit to the smart card.
 *
 * @param apdu_iso_case APDU ISO case
 * @param cla class byte
 * @param ins instruction byte
 * @param p1 parameter byte 1
 * @param p2 parameter byte 2
 * @param lc length of command data to be sent
 * @param data command data of length lc
 * @param le the length of data expected to be returned after processing the command
 * @param pbSendBuffer buffer where the APDU command will be stored
 * @param dwSendLength total length of the APDU command
 * @return 0 if success else -1
 */
extern int apdu_build_command(apdu_iso_case_t apdu_iso_case, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint16_t lc, uint8_t *data, uint16_t le, uint8_t *pbSendBuffer, uint32_t *dwSendLength);

#ifdef __cplusplus
}
#endif

#endif /* __SECURITY_SCHEME_APDU_COMMAND_H_ */
