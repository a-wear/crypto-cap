/*
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

package security_scheme;

public class Config {

    /*
     * AES config
     */
    public static final short AES_BLOCK_SIZE = 16; // 128 bits
    public static final short AES_IV_LENGTH = 16; // 128 bits

    /*
     * Length of nonce
     */
    public static final short NONCE_LENGTH = 16;

    /*
     * Maximum length of user id
     */
    public static final short USER_MAX_ID_LENGTH = 16;

    /*
     * Maximum length of verifier id
     */
    public static final short VERIFIER_MAX_ID_LENGTH = 16;

    /*
     * Authentication codes
     */
    public static final short AUTHENTICATION_OK = (short) 0x9001;
    public static final short AUTHENTICATION_ERR = (short) 0x9002;
}
