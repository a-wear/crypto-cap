/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.mpo2hceauth;

import com.example.mpo2hceauth.Crypto.ECCOP_Elliptic_curves;
import com.example.mpo2hceauth.utils.Convert;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.math.ec.ECPoint;

/**
 *
 * @author dzurenda
 */
public class UserWBB {


    public static int CURVE_SIZE    =  32;      // size of RND in bytes
    public static int CURVE_POINT__SIZE    =  65;      // size of RND in bytes
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

    public UserWBB(){

        this.ec = ec = new ECCOP_Elliptic_curves();

        sRND = new SecureRandom();
    }

    public void init(byte[] data){

        byte[] KuiBytes = new byte[CURVE_POINT__SIZE];
        byte[] KuiCommaBytes  = new byte[CURVE_POINT__SIZE];

        byte[] ID_uiBytes = new byte[CURVE_SIZE];
        System.arraycopy(data, APDU_DATA_OFFSET,ID_uiBytes,0,ID_uiBytes.length);
        this.ID_ui = Convert.byteArrayToBigInt(ID_uiBytes);

        System.arraycopy(data, APDU_DATA_OFFSET+ID_uiBytes.length,KuiBytes,0,KuiBytes.length);
        System.arraycopy(data, APDU_DATA_OFFSET+KuiBytes.length+ID_uiBytes.length,KuiCommaBytes,0,KuiCommaBytes.length);
        this.Kui = ec.getCurve().decodePoint(KuiBytes);
        this.KuiComma = ec.getCurve().decodePoint(KuiCommaBytes);

    }

    public UserWBB(ECPoint[] Ku, BigInteger ID_ui, ECCOP_Elliptic_curves ec){
        this.Kui = Ku[0];
        this.KuiComma = Ku[1];
        this.ID_ui = ID_ui;
        this.ec = ec;

        sRND = new SecureRandom();
    }

    public byte[] message1(byte[] data) throws NoSuchAlgorithmException{

        byte[] nonce = new byte[CURVE_SIZE];
        System.arraycopy(data, APDU_DATA_OFFSET, nonce, 0, nonce.length);

        BigInteger r = new BigInteger(User.CURVE_SIZE, sRND);
        BigInteger rho = new BigInteger(User.CURVE_SIZE, sRND);
        BigInteger rho_ID = new BigInteger(User.CURVE_SIZE, sRND);

        ECPoint Kui_HAT = Kui.multiply(r);
        ECPoint KuiComma_HAT = KuiComma.multiply(r);
        ECPoint t = ec.getG().multiply(rho).add(KuiComma_HAT.multiply(rho_ID));

        MessageDigest mDigest = MessageDigest.getInstance("SHA1");

        mDigest.update(Kui_HAT.getEncoded(false));
        mDigest.update(t.getEncoded(false));
        byte[] hash = mDigest.digest(nonce);
        // hash output 20B need to be added to CURVE_SIZE B array
        byte[] e_Bytes = new byte[User.CURVE_SIZE];
        System.arraycopy(hash, 0, e_Bytes, e_Bytes.length-hash.length, hash.length);


        BigInteger e = new BigInteger(e_Bytes);

        BigInteger s = rho.add(e.multiply(r)).mod(ec.getQ());
        BigInteger s_ID = rho_ID.subtract(e.multiply(ID_ui)).mod(ec.getQ());

        byte[] Kui_HAT_Bytes = Kui_HAT.getEncoded(false);

        byte[] s_Bytes0 = s.toByteArray();
        byte[] s_Bytes = new byte[User.CURVE_SIZE];
        System.arraycopy(s_Bytes0, 0, s_Bytes, s_Bytes.length-s_Bytes0.length, s_Bytes0.length);


        byte[] s_ID_Bytes0 = Convert.bigIntToByteArray(s_ID);                                 //if starts with 00 (31 B) long big integer, algorithm fails
        System.out.println("USER: s_ID_Bytes0 ="+s_ID_Bytes0.length);
        System.out.println("USER: s_ID_Bytes0 ="+Convert.bytesToHex(s_ID_Bytes0));
        byte[] s_ID_Bytes = new byte[User.CURVE_SIZE];
        System.arraycopy(s_ID_Bytes0, 0, s_ID_Bytes, s_ID_Bytes.length-s_ID_Bytes0.length, s_ID_Bytes0.length);


        byte[] uProof = new byte[Kui_HAT_Bytes.length+e_Bytes.length+s_Bytes.length+s_ID_Bytes.length];
        System.arraycopy(Kui_HAT_Bytes, 0, uProof, 0, Kui_HAT_Bytes.length);
        System.arraycopy(e_Bytes, 0, uProof, Kui_HAT_Bytes.length, e_Bytes.length);
        System.arraycopy(s_Bytes, 0, uProof, Kui_HAT_Bytes.length+e_Bytes.length, s_Bytes.length);
        System.arraycopy(s_ID_Bytes, 0, uProof, Kui_HAT_Bytes.length+e_Bytes.length+s_Bytes.length, s_ID_Bytes.length);

        System.out.println("USER: e ="+e_Bytes.length);
        System.out.println("USER: s ="+s_Bytes.length);
        System.out.println("USER: sID ="+s_ID_Bytes.length);
        System.out.println("USER: e ="+uProof.length);

        System.out.println("USER: Kui ="+Kui);
        System.out.println("USER: KuiComma ="+KuiComma);
        System.out.println("USER: e ="+e);
        System.out.println("USER: s ="+s);
        System.out.println("USER: sID ="+s_ID);
        System.out.println("USER: t ="+Convert.bytesToHex(t.getEncoded(false)));
        System.out.println("USER: e HASH ="+Convert.bytesToHex(hash));
        System.out.println("USER: Kui_HAT ="+Convert.bytesToHex(Kui_HAT.getEncoded(false)));
        System.out.println("USER: nonce ="+Convert.bytesToHex(nonce));

        System.out.println("USER: Proof: "+Convert.bytesToHex(uProof));

        return uProof;
    }



}
