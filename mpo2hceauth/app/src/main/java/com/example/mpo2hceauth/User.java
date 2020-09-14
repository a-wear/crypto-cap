/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.example.mpo2hceauth;

import com.example.mpo2hceauth.Crypto.*;
import com.example.mpo2hceauth.utils.Convert;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 *
 * @author dzurenda
 */
public class User {

    public static int RND_SIZE      =  16;      // size of RND in bytes
    public static int CURVE_SIZE    =  32;      // size of RND in bytes
    public static int KEY_SIZE      =  16;      // size of RND in bytes
    public static int IV_GCM_SIZE   =  12;      // size of RND in bytes
    public static int APDU_DATA_OFFSET      =  5;

    private static String USER_STRING = "User";  
    private static String VERIFIER_STRING = "Verifier";

    // "000000000000User"
    byte[] userString = {
            (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30,
            (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x55, (byte) 0x73, (byte) 0x65, (byte) 0x72
    };

    // "00000000Verifier"
    byte[] verifierString = {
            (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30, (byte) 0x30,
            (byte) 0x56, (byte) 0x65, (byte) 0x72, (byte) 0x69, (byte) 0x66, (byte) 0x69, (byte) 0x65, (byte) 0x72
    };

    private byte[] ID_ui        = null;
    private byte[] K_vi_ui      = null;
    
    private byte[] iv           =  null;
    private SecureRandom sRND   = null;
    
    private byte[] ID_vi        = null;
    private byte[] vnonce       =  null;
    private byte[] unonce       =  null;
    private byte[] ukey         =  null;
    private byte[] vkey         =  null;
    private byte[] uAuthData    =  null;
    private byte[] Ks           =  null;

    public User(){


        this.ID_ui = new byte[User.RND_SIZE];
        this.K_vi_ui = new byte[User.KEY_SIZE];
        this.ID_vi = new byte[User.RND_SIZE];
        this.vnonce = new byte[User.RND_SIZE];


        sRND = new SecureRandom();
        iv = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};  // 12B inicialization vector IV

        Ks = new byte[User.RND_SIZE];
    }

    public User(byte[] ID_ui, byte[] K_vi_ui){
        this.ID_ui = ID_ui;
        this.K_vi_ui = K_vi_ui;
        
        sRND = new SecureRandom();
        iv = new byte[]{(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                        (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};  // 12B inicialization vector IV
        
        Ks = new byte[User.RND_SIZE];
    }

    public void init(byte[] data){
        System.arraycopy(data, APDU_DATA_OFFSET, ID_ui, 0, ID_ui.length);
        System.arraycopy(data, APDU_DATA_OFFSET+ID_ui.length, K_vi_ui, 0, K_vi_ui.length);
    }
    
    public byte[] message1(){
        
        unonce = sRND.generateSeed(User.RND_SIZE);
        return unonce;
    }

    public byte[] message2(byte[] data){

        System.arraycopy(data, APDU_DATA_OFFSET, ID_vi, 0, ID_vi.length);
        System.arraycopy(data, APDU_DATA_OFFSET+ID_vi.length, vnonce, 0, vnonce.length);

        iv = sRND.generateSeed(User.IV_GCM_SIZE);

        try {

            // enncrypt input data "USER_STRING" with key K_vi_ui, output ukey
           // ukey = AESecb.doEncrypt(Convert.hexStringToByteArray(USER_STRING),
            ukey = AESecb.doEncrypt(userString,
                    iv,
                    AESecb.setKey(K_vi_ui));

            System.out.println("USER: ukey computed: "+Convert.bytesToHex(ukey));

            // enncrypt input data "VERIFIER_STRING" with key K_vi_ui, output vkey
            //vkey = AESecb.doEncrypt(Convert.hexStringToByteArray(VERIFIER_STRING),
            vkey = AESecb.doEncrypt(verifierString,
                    iv,
                    AESecb.setKey(K_vi_ui));

            System.out.println("USER: vkey computed: "+Convert.bytesToHex(ukey));

            uAuthData = new byte[ID_ui.length + ID_vi.length + unonce.length + vnonce.length];
            System.arraycopy(ID_ui, 0, uAuthData, 0, ID_ui.length);
            System.arraycopy(ID_vi, 0, uAuthData, ID_ui.length, ID_vi.length);
            System.arraycopy(unonce, 0, uAuthData, ID_ui.length + ID_vi.length, unonce.length);
            System.arraycopy(vnonce, 0, uAuthData, ID_ui.length + ID_vi.length + unonce.length, vnonce.length);



            // enncrypt input data "uAuthData" with key K_vi_ui, output vkey
            byte[] uCiphertext = AESgcm.doEncrypt(
                    uAuthData,
                    iv,
                    AESgcm.setKey(ukey));

            System.out.println("USER: Ciphertext: "+Convert.bytesToHex(uCiphertext));

            byte[] outputData = new byte[IV_GCM_SIZE+uCiphertext.length];
            System.arraycopy(iv,0, outputData, 0, iv.length);
            System.arraycopy(uCiphertext,0, outputData, iv.length, uCiphertext.length);


            return outputData;

        } catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException
                | InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
                | UnsupportedEncodingException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }

    }

    public byte[] message2(byte[] ID_vi, byte[] vnonce){
        
        this.ID_vi = ID_vi;
        this.vnonce = vnonce;
        
        
		try {
                    
                    // enncrypt input data "USER_STRING" with key K_vi_ui, output ukey 
                        ukey = AESecb.doEncrypt(Convert.hexStringToByteArray(USER_STRING),
					iv, 
					AESecb.setKey(K_vi_ui));
		
                        System.out.println("USER: ukey computed: "+Convert.bytesToHex(ukey));
                        
                    // enncrypt input data "VERIFIER_STRING" with key K_vi_ui, output vkey 
                        vkey = AESecb.doEncrypt(Convert.hexStringToByteArray(VERIFIER_STRING),
					iv, 
					AESecb.setKey(K_vi_ui));
		
                        System.out.println("USER: vkey computed: "+Convert.bytesToHex(ukey));
                        
                    uAuthData = new byte[ID_ui.length + ID_vi.length + unonce.length + vnonce.length];
                    System.arraycopy(ID_ui, 0, uAuthData, 0, ID_ui.length);
                    System.arraycopy(ID_vi, 0, uAuthData, ID_ui.length, ID_vi.length);
                    System.arraycopy(unonce, 0, uAuthData, ID_ui.length + ID_vi.length, unonce.length);
                    System.arraycopy(vnonce, 0, uAuthData, ID_ui.length + ID_vi.length + unonce.length, vnonce.length);
                    
                    
                    
                    // enncrypt input data "uAuthData" with key K_vi_ui, output vkey 
                        byte[] uCiphertext = AESgcm.doEncrypt(
					uAuthData,
					iv, 
					AESgcm.setKey(ukey));
		
                        System.out.println("USER: Ciphertext: "+Convert.bytesToHex(uCiphertext));
                        return uCiphertext;
                        
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
           
    }
    
    public int message3(byte[] vCiphertext){

        iv = new byte[IV_GCM_SIZE];
        System.arraycopy(vCiphertext, APDU_DATA_OFFSET,iv,0,iv.length);
        byte[] ciphertext = new byte[vCiphertext.length-APDU_DATA_OFFSET-IV_GCM_SIZE];
        System.arraycopy(vCiphertext, APDU_DATA_OFFSET+IV_GCM_SIZE,ciphertext,0,ciphertext.length);

       // byte[] ciphertext = new byte[vCiphertext.length-APDU_DATA_OFFSET];
       // System.arraycopy(vCiphertext, APDU_DATA_OFFSET,ciphertext,0,ciphertext.length);
        
		try {
                    
                   // decrypt input data "vCiphertext" with key vkey, output message - check the content of the message 
                   // and get session key Ks 
                        byte[] decrypted = AESgcm.doDecrypt(
                                ciphertext,
					iv, 
					AESgcm.setKey(vkey));
			System.out.println("USER: decrypted message: "+Convert.bytesToHex(decrypted));
                    
                        
                        
                    byte[] vAuthData = new byte[ID_ui.length + ID_vi.length + unonce.length + vnonce.length];
                    System.arraycopy(ID_vi, 0, vAuthData, 0, ID_vi.length);
                    System.arraycopy(ID_ui, 0, vAuthData, ID_vi.length, ID_ui.length);
                    System.arraycopy(vnonce, 0, vAuthData, ID_ui.length + ID_vi.length, vnonce.length);
           
                    for(int i=0; i<vAuthData.length; i++){
                            if(decrypted[0]!=vAuthData[0]){
                              System.err.println("USER: authentication failed: ");
                              return 0;
                            }
                        }
                    
                    
                    System.arraycopy(decrypted, ID_ui.length + ID_vi.length + unonce.length + vnonce.length, Ks, 0, User.RND_SIZE);
                    
                    System.out.println("USER: authentication succes: ");
                    System.out.println("USER: Ks = "+Convert.bytesToHex(Ks));
                    
      
                        
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
            return 0;
		}
        return 1;
    }

    public byte[] getKs() {
        return Ks;
    }

    public byte[] getUkey() {
        return ukey;
    }

    public byte[] getK_vi_ui() {
        return K_vi_ui;
    }
}
