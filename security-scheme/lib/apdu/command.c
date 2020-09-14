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

#include "command.h"

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
int apdu_build_command(apdu_iso_case_t apdu_iso_case, uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2, uint16_t lc, uint8_t *data, uint16_t le, uint8_t *pbSendBuffer, uint32_t *dwSendLength)
{
    if (pbSendBuffer == NULL || (*dwSendLength != MAX_APDU_LENGTH_T0 && *dwSendLength != MAX_APDU_LENGTH_T1))
    {
#ifndef NDEBUG
        const char *apdu_iso_case_string[] = {"CASE1", "CASE2S", "CASE2E", "CASE3S", "CASE3E", "CASE4S", "CASE4E"};
        fprintf(stderr, "Error: apdu_iso_case=%s; *dwSendLength=%u; lc=%u; le=%u\n", apdu_iso_case_string[apdu_iso_case], *dwSendLength, lc, le);
#endif
        return -1;
    }

    // check lc, data and le
    if (apdu_iso_case == CASE2S && le > MAX_APDU_RECV_SIZE_T0)
    {
#ifndef NDEBUG
        fprintf(stderr, "Error: CASE2S; le=%u > MAX_APDU_RECV_SIZE_T0=%u\n", le, MAX_APDU_RECV_SIZE_T0);
#endif
        return -1;
    }
    else if (apdu_iso_case == CASE2E && le > MAX_APDU_RECV_SIZE_T1)
    {
#ifndef NDEBUG
        fprintf(stderr, "Error: CASE2E; le=%u > MAX_APDU_RECV_SIZE_T1=%u\n", le, MAX_APDU_RECV_SIZE_T1);
#endif
        return -1;
    }
    else if (apdu_iso_case == CASE3S && (data == NULL || lc > MAX_APDU_SEND_SIZE_T0))
    {
#ifndef NDEBUG
        fprintf(stderr, "Error: CASE3S; data=%p; lc=%u > MAX_APDU_SEND_SIZE_T0=%u\n", data, lc, MAX_APDU_SEND_SIZE_T0);
#endif
        return -1;
    }
    else if (apdu_iso_case == CASE3E && (data == NULL || lc > MAX_APDU_SEND_SIZE_T1))
    {
#ifndef NDEBUG
        fprintf(stderr, "Error: CASE3E; data=%p; lc=%u > MAX_APDU_SEND_SIZE_T1=%u\n", data, lc, MAX_APDU_SEND_SIZE_T1);
#endif
        return -1;
    }
    else if (apdu_iso_case == CASE4S && (data == NULL || lc > MAX_APDU_SEND_SIZE_T0 || le > MAX_APDU_RECV_SIZE_T0))
    {
#ifndef NDEBUG
        fprintf(stderr, "Error: CASE4S; data=%p; lc=%u > MAX_APDU_SEND_SIZE_T0=%u; le=%u > MAX_APDU_RECV_SIZE_T0=%u\n", data, lc, MAX_APDU_SEND_SIZE_T0, le, MAX_APDU_RECV_SIZE_T0);
#endif
        return -1;
    }
    else if (apdu_iso_case == CASE4E && (data == NULL || lc > MAX_APDU_SEND_SIZE_T1 || le > MAX_APDU_RECV_SIZE_T1))
    {
#ifndef NDEBUG
        fprintf(stderr, "Error: CASE4E; data=%p; lc=%u > MAX_APDU_SEND_SIZE_T1=%u; le=%u > MAX_APDU_RECV_SIZE_T1=%u\n", data, lc, MAX_APDU_SEND_SIZE_T1, le, MAX_APDU_RECV_SIZE_T1);
#endif
        return -1;
    }

    switch (apdu_iso_case)
    {
        case CASE1:
        {
            pbSendBuffer[0] = cla;
            pbSendBuffer[1] = ins;
            pbSendBuffer[2] = p1;
            pbSendBuffer[3] = p2;
            *dwSendLength = 4;
            break;
        }
        case CASE2S:
        {
            pbSendBuffer[0] = cla;
            pbSendBuffer[1] = ins;
            pbSendBuffer[2] = p1;
            pbSendBuffer[3] = p2;
            pbSendBuffer[4] = le;
            *dwSendLength = 5;
            break;
        }
        case CASE2E:
        {
            pbSendBuffer[0] = cla;
            pbSendBuffer[1] = ins;
            pbSendBuffer[2] = p1;
            pbSendBuffer[3] = p2;
            pbSendBuffer[4] = 00;
            pbSendBuffer[5] = le >> 8u;
            pbSendBuffer[6] = le;
            *dwSendLength = 7;
            break;
        }
        case CASE3S:
        {
            pbSendBuffer[0] = cla;
            pbSendBuffer[1] = ins;
            pbSendBuffer[2] = p1;
            pbSendBuffer[3] = p2;
            pbSendBuffer[4] = lc;
            memcpy(&pbSendBuffer[5], data, lc);
            *dwSendLength = 5 + lc;
            break;
        }
        case CASE3E:
        {
            pbSendBuffer[0] = cla;
            pbSendBuffer[1] = ins;
            pbSendBuffer[2] = p1;
            pbSendBuffer[3] = p2;
            pbSendBuffer[4] = 00;
            pbSendBuffer[5] = lc >> 8u;
            pbSendBuffer[6] = lc;
            memcpy(&pbSendBuffer[7], data, lc);
            *dwSendLength = 7 + lc;
            break;
        }
        case CASE4S:
        {
            pbSendBuffer[0] = cla;
            pbSendBuffer[1] = ins;
            pbSendBuffer[2] = p1;
            pbSendBuffer[3] = p2;
            pbSendBuffer[4] = lc;
            memcpy(&pbSendBuffer[5], data, lc);
            pbSendBuffer[5 + lc] = le;
            *dwSendLength = 5 + lc + 1;
            break;
        }
        case CASE4E:
        {
            pbSendBuffer[0] = cla;
            pbSendBuffer[1] = ins;
            pbSendBuffer[2] = p1;
            pbSendBuffer[3] = p2;
            pbSendBuffer[4] = 00;
            pbSendBuffer[5] = lc >> 8u;
            pbSendBuffer[6] = lc;
            memcpy(&pbSendBuffer[7], data, lc);
            pbSendBuffer[7 + lc] = 00;
            pbSendBuffer[7 + lc + 1] = le >> 8u;
            pbSendBuffer[7 + lc + 2] = le;
            *dwSendLength = 7 + lc + 3;
            break;
        }
        default:
        {
            *dwSendLength = 0;
            break;
        }
    }

    return 0;
}
