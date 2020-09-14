package com.example.mpo2hceauth;

import android.util.Log;

import com.example.mpo2hceauth.Crypto.ECCOP_Elliptic_curves;
import com.example.mpo2hceauth.utils.Convert;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static com.example.mpo2hceauth.utils.Convert.byteToHex;

/**
 * Created by Petr Dzurenda on 26.08.2015.
 * Class represent APDU messages
 */
public class APDU {

    private final int EMPTY       = 4;
    private final int setLcLe     = 5;

    public final static byte OFFSET_CLA      = (byte) 0x00;
    public final static byte OFFSET_INT      = (byte) 0x01;
    public final static byte OFFSET_P1       = (byte) 0x02;
    public final static byte OFFSET_P2       = (byte) 0x03;
    public final static byte OFFSET_LC       = (byte) 0x04;

    private byte CLA;
    private byte INS;
    private byte P1;
    private byte P2;
    private byte Lc;
    private byte[] data;
    private byte Le;

    private byte[] command      = null;

    /**
     * Empty constructor
     */
    public APDU(){}

    /**
     * Constructor with APDU command data
     * @param apdu  byte array of APDU command
     */
    public APDU(byte[] apdu){

        if(apdu.length < 4)
            return;

        this.CLA = apdu[0];
        this.INS = apdu[1];
        this.P1 = apdu[2];
        this.P2 = apdu[3];

        getData(apdu);
    }


    /**
     * APDU Command type 1, (Header || no data || no request of data)
     * @param CLA   Class
     * @param INT   Instantiation
     * @param P1    Parameter 1
     * @param P2    Parameter 2
     * @return  APDU command type 1
     */
    public byte[] commAPDU(byte CLA, byte INT, byte P1, byte P2){

        command = new byte[4];
        command[OFFSET_CLA] = CLA;
        command[OFFSET_INT] = INT;
        command[OFFSET_P1] = P1;
        command[OFFSET_P2] = P2;

        return command;
    }


    /**
     * APDU Command type 2, (Header || no data || request of data)
     * @param CLA   Class
     * @param INT   Instantiation
     * @param P1    Parameter 1
     * @param P2    Parameter 2
     * @param Le    request of response data with length of Le
     * @return  APDU command type 2
     */
    public byte[] commAPDU(byte CLA, byte INT, byte P1, byte P2, byte Le){

        command = new byte[5];
        command[OFFSET_CLA] = CLA;
        command[OFFSET_INT] = INT;
        command[OFFSET_P1] = P1;
        command[OFFSET_P2] = P2;
        command[command.length-1] = Le;

        return command;
    }


    /**
     *
     * APDU Command type 3, (Header || data || no request of data)
     * @param CLA   Class
     * @param INT   Instantiation
     * @param P1    Parameter 1
     * @param P2    Parameter 2
     * @param data  byte array of payload (transferred data)
     * @return  APDU command type 3
     */
    public byte[] commAPDU(byte CLA, byte INT, byte P1, byte P2, byte[] data){

        command = new byte[data.length+5];
        command[OFFSET_CLA] = CLA;
        command[OFFSET_INT] = INT;
        command[OFFSET_P1] = P1;
        command[OFFSET_P2] = P2;
        command[OFFSET_LC] = (byte) data.length;

        System.arraycopy(data, 0, command, 5, data.length);

        return command;
    }


    /**
     * APDU Command type 4, (Header || data || request of data)
     * @param CLA   Class
     * @param INT   Instantiation
     * @param P1    Parameter 1
     * @param P2    Parameter 2
     * @param Lc    length of payload
     * @param data  byte array of payload (transferred data)
     * @param Le    request of response data with length of Le
     * @return  APDU command type 4
     */
    public byte[] commAPDU(byte CLA, byte INT, byte P1, byte P2, byte Lc, byte[] data, byte Le){

        command = new byte[data.length+6];
        command[OFFSET_CLA] = CLA;
        command[OFFSET_INT] = INT;
        command[OFFSET_P1] = P1;
        command[OFFSET_P2] = P2;
        command[OFFSET_LC] = Lc;
        command[command.length - 1] = Le;

        System.arraycopy(data, 0, command, 5, data.length);

        return command;
    }


    /**
     * Method creates response APDU (data || code (SW1 || SW2))
     * @param data
     * @return
     */
    public byte[] responseAPDU(byte[] data){

        if(data.length == this.Le || this.Le == 0)
            return Util.arrayCombine(data, rCodeAPDU.PROCESS_SUCESS);
        else
            return Util.arrayCombine(data, rCodeAPDU.WRONG_LENGTH);
    }


    /**
     * Private method takes payload (transferred data) from APDU command message
     * @param apdu  byte array of APDU command
     */
    private void getData(byte[] apdu){

        if(apdu.length == EMPTY)
            return;

        else if (apdu.length == setLcLe)
            this.Le = apdu[4];

        else if (apdu.length == 5 + Convert.byteToHex(apdu[4])){
            this.Lc = apdu[4];
            this.data = new byte[Convert.byteToHex(Lc)];
            System.arraycopy(apdu, 5, this.data, 0, this.data.length);
        }

        else{
            this.Lc = apdu[4];
            this.data = new byte[Lc];
            System.arraycopy(apdu, 5, this.data, 0, Lc);
            this.Le = apdu[apdu.length - 1];
        }
    }

    public void fromByteArrayApdu(byte[] byteArreyApdu){

        if(byteArreyApdu.length >= 4 ){
            CLA = byteArreyApdu[0];
            INS = byteArreyApdu[1];
            P1 = byteArreyApdu[2];
            P2 = byteArreyApdu[3];

            if(byteArreyApdu.length == 5) {   // jeli 5 obsahuje požadavek na delku dat
                Le = byteArreyApdu[4];
            }

            if(byteArreyApdu.length > 5){   // obsahuje tělo APDU, je zde určitě Lc

                Lc = byteArreyApdu[4];

                if(byteArreyApdu.length == (5 + Lc)) {    // obsahuje pouze data
                    data = new byte[Lc];
                    System.arraycopy(byteArreyApdu, 5, this.data, 0, Lc);
                }

                else if (byteArreyApdu.length == (5 + Lc + 1) && Lc != 0) {  // obsahuje také Le, tj požadavek na délku vrácených dat
                    Le = byteArreyApdu[5 + Lc];
                    data = new byte[Lc];
                    System.arraycopy(byteArreyApdu, 5, this.data, 0, Lc);
                }

                else if (byteArreyApdu.length == (5 + Lc + 1) && Lc == 0) {  // obsahuje také Le, tj požadavek na délku vrácených dat
                    Le = byteArreyApdu[5];
                }

                else {  // špatná délka dat
                    Log.e("APDU", "Wrong data length!");
                }
            }
        }else{
            Log.e("APDU", "Wrong data!");
        }
    }


    public byte getCLA() {
        return CLA;
    }

    public byte getINS() {
        return INS;
    }

    public byte getLc() {
        return Lc;
    }

    public byte getLe() {
        return Le;
    }

    public byte getP1() {
        return P1;
    }

    public byte getP2() {
        return P2;
    }

    public byte[] getData() {
        return data;
    }

    /**
     *
     * @author dzurenda
     */
    public static class UserWBB {

        public static int CURVE_SIZE    =  32;      // size of RND in bytes
        public static int APDU_DATA_OFFSET      =  5;

        private ECPoint Kui         = null;
        private ECPoint KuiComma    = null;
        private BigInteger ID_ui    = null;

        private SecureRandom sRND   = null;

        private ECCOP_Elliptic_curves ec = null;

        //-------------------------------------
        private static String USER_STRING = "User";
        private static String VERIFIER_STRING = "Verifier";

        private byte[] K_vi_ui      = null;

        private byte[] iv           =  null;


        private byte[] ID_vi        = null;
        private byte[] vnonce       =  null;
        private byte[] unonce       =  null;
        private byte[] ukey         =  null;
        private byte[] vkey         =  null;
        private byte[] uAuthData    =  null;
        private byte[] Ks           =  null;

        public UserWBB(ECPoint[] Ku, BigInteger ID_ui, ECCOP_Elliptic_curves ec){
            this.Kui = Ku[0];
            this.KuiComma = Ku[1];
            this.ID_ui = ID_ui;
            this.ec = ec;

            sRND = new SecureRandom();
        }

        public byte[] message1(byte[] nonce) throws NoSuchAlgorithmException {

            BigInteger r = new BigInteger(UserWBB.CURVE_SIZE, sRND);
            BigInteger rho = new BigInteger(UserWBB.CURVE_SIZE, sRND);
            BigInteger rho_ID = new BigInteger(UserWBB.CURVE_SIZE, sRND);

            ECPoint Kui_HAT = Kui.multiply(r);
            ECPoint KuiComma_HAT = KuiComma.multiply(r);
            ECPoint t = ec.getG().multiply(rho).add(KuiComma_HAT.multiply(rho_ID));

            MessageDigest mDigest = MessageDigest.getInstance("SHA1");

            mDigest.update(Kui_HAT.getEncoded(false));
            mDigest.update(t.getEncoded(false));
            byte[] hash = mDigest.digest(nonce);
            // hash output 20B need to be added to CURVE_SIZE B array
            byte[] e_Bytes = new byte[UserWBB.CURVE_SIZE];
            System.arraycopy(hash, 0, e_Bytes, e_Bytes.length-hash.length, hash.length);


            BigInteger e = new BigInteger(e_Bytes);

            BigInteger s = rho.add(e.multiply(r)).mod(ec.getQ());
            BigInteger s_ID = rho_ID.subtract(e.multiply(ID_ui)).mod(ec.getQ());

            byte[] Kui_HAT_Bytes = Kui_HAT.getEncoded(false);

            byte[] s_Bytes0 = s.toByteArray();
            byte[] s_Bytes = new byte[UserWBB.CURVE_SIZE];
            System.arraycopy(s_Bytes0, 0, s_Bytes, s_Bytes.length-s_Bytes0.length, s_Bytes0.length);


            byte[] s_ID_Bytes0 = Convert.bigIntToByteArray(s_ID);                                 //if starts with 00 (31 B) long big integer, algorithm fails
            System.out.println("USER: s_ID_Bytes0 ="+s_ID_Bytes0.length);
            System.out.println("USER: s_ID_Bytes0 ="+Convert.bytesToHex(s_ID_Bytes0));
            byte[] s_ID_Bytes = new byte[UserWBB.CURVE_SIZE];
            System.arraycopy(s_ID_Bytes0, 0, s_ID_Bytes, s_ID_Bytes.length-s_ID_Bytes0.length, s_ID_Bytes0.length);


            byte[] uProof = new byte[Kui_HAT_Bytes.length+e_Bytes.length+s_Bytes.length+s_ID_Bytes.length];
            System.arraycopy(Kui_HAT_Bytes, 0, uProof, 0, Kui_HAT_Bytes.length);
            System.arraycopy(e_Bytes, 0, uProof, Kui_HAT_Bytes.length, e_Bytes.length);
            System.arraycopy(s_Bytes, 0, uProof, Kui_HAT_Bytes.length+e_Bytes.length, s_Bytes.length);
            System.arraycopy(s_ID_Bytes, 0, uProof, Kui_HAT_Bytes.length+e_Bytes.length+s_Bytes.length, s_ID_Bytes.length);

            System.out.println("USER: e ="+Kui_HAT_Bytes.length);
            System.out.println("USER: e ="+e_Bytes.length);
            System.out.println("USER: e ="+s_Bytes.length);
            System.out.println("USER: e ="+s_ID_Bytes.length);
            System.out.println("USER: e ="+uProof.length);

            System.out.println("USER: KuiComma_HAT ="+Convert.bytesToHex(Kui_HAT_Bytes));
            System.out.println("USER: e ="+e);
            System.out.println("USER: s ="+s);
            System.out.println("USER: sID ="+s_ID);
            System.out.println("USER: t ="+Convert.bytesToHex(t.getEncoded(false)));
            System.out.println("USER: e HASH ="+Convert.bytesToHex(hash));

            System.out.println("USER: Proof: "+Convert.bytesToHex(uProof));

            return uProof;
        }



    }
}
