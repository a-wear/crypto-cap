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

#include "epoch_helper.h"

/**
 * Generates the epoch with the current date (dd-mm-yyyy).
 *
 * @param epoch the epoch to be generated
 * @param epoch_length the length of the epoch
 * @return 0 if success else -1
 */
int generate_epoch(void *epoch, size_t epoch_length)
{
    struct tm *tm_info;
    time_t time_info;

    if (epoch == NULL || epoch_length != EPOCH_LENGTH)
    {
        return -1;
    }

    // current epoch
    time(&time_info);
    tm_info = localtime(&time_info);
    ((uint8_t *) epoch)[0] = tm_info->tm_mday; // day of the month
    ((uint8_t *) epoch)[1] = tm_info->tm_mon; // month of the year
    ((uint8_t *) epoch)[2] = ((unsigned int) tm_info->tm_year >> 8u) & 0xFFu; // year (high byte)
    ((uint8_t *) epoch)[3] = tm_info->tm_year; // year (low byte)

    return 0;
}