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

import javacard.framework.Util;

public class VerifierController {

    /**
     * Verifier model
     */
    private final VerifierModel model;

    /**
     * Default VerifierController constructor.
     */
    public VerifierController() {
        model = new VerifierModel();
    }

    /**
     * Gets the verifier identifier.
     *
     * @return the verifier identifier
     */
    public byte[] getIdentifier() {
        return model.getIdentifier();
    }

    /**
     * Gets the verifier nonce.
     *
     * @return the verifier nonce
     */
    public byte[] getNonce() {
        return model.getNonce();
    }

    /**
     * Initializes the verifier entity using the raw data.
     *
     * @param data verifier raw data used to initialise the entity
     */
    public void initialize(byte[] data) {
        short offset = 0;

        // verifier identifier
        Util.arrayCopyNonAtomic(data, offset, model.getIdentifier(), (short) 0, Config.VERIFIER_MAX_ID_LENGTH);
        offset += Config.VERIFIER_MAX_ID_LENGTH;

        // verifier nonce
        Util.arrayCopyNonAtomic(data, offset, model.getNonce(), (short) 0, Config.NONCE_LENGTH);
    }
}
