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

#include "setup.h"

/**
 * Outputs the system parameters.
 *
 * @param parameters the system parameters
 * @return 0 if success else -1
 */
int sys_setup(system_par_t *parameters)
{
    char G1_buffer[] = "1 " // affine coordinate
                       "-1 " // x
                       "1"; // y

    int r;

    if (parameters == NULL)
    {
        return -1;
    }

    parameters->curve = MCL_BN254;
    r = mclBn_init(parameters->curve, MCLBN_COMPILED_TIME_VAR);
    if (r != 0)
    {
        return -2;
    }

    // initialize G1 (sizeof -1 to remove the null character at the end)
    mclBnG1_setStr(&parameters->G1, (const char *) G1_buffer, sizeof(G1_buffer) - 1, 10);
    r = mclBnG1_isValid(&parameters->G1);
    if (r != 1)
    {
        return -3;
    }

    return 0;
}
