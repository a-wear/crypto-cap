/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.mpo2hceauth.utils;


/**
 *
 * @author dzurenda
 */
public class APDU {
    
    private static byte[] baCommandAPDU;

   
    /**
     * Create APDU command
     *
     * @param CLA
     * @param INS
     * @param P1
     * @param P2
     * @param Lc
     * @param data
     * @param Le
     * @return
     */
    public byte[] createAPDUComm(byte CLA, byte INS, byte P1, byte P2, int Lc, byte[] data, byte Le) {

        byte[] apduComm;
        int LcSize = 1;
        int LeSize = 1;

        if (Lc > 255) {
            LcSize = 3;
        }

        if (Lc > 255) {
            LeSize = 3;
        }

        if (Le == 0 && Lc == 0) {                                         //Case 1
            apduComm = new byte[4];
        } else if (Le != 0 && Lc == 0) {                                   //Case 2
            apduComm = new byte[5];
            apduComm[apduComm.length - 1] = Le;

        } else if (Le == 0 && Lc != 0) //Case 3
        {
            apduComm = new byte[4 + LcSize + data.length];
        } else if (Le != 0 && Lc != 0) {                                   //Case 4
            apduComm = new byte[4 + LcSize + data.length + LeSize];
            apduComm[apduComm.length - 1] = Le;
        } else {
            return null;
        }

        apduComm[0] = CLA;
        apduComm[1] = INS;
        apduComm[2] = P1;
        apduComm[3] = P2;

        if (Lc != 0) {
            apduComm[4] = (byte) data.length;
            System.arraycopy(data, 0, apduComm, 5, data.length);
        }

        return apduComm;
    }
    
}
