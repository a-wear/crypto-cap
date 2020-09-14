package com.example.mpo2hceauth;

/**
 * Created by Petr Dzurenda on 26.08.2015.
 * APDU responses codes from HCE (Host Card Emulation)
 */
public class rCodeAPDU {

    public static byte[] PROCESS_SUCESS     = new byte[] {(byte)0x90,(byte)0x00};
    public static byte[] WRONG_CLASS          = new byte[] {(byte)0x6E,(byte)0x00};
    public static byte[] WRONG_INSTANCE       = new byte[] {(byte)0x6D,(byte)0x00};
    public static byte[] WRONG_COMPUTATION      = new byte[] {(byte)0x67,(byte)0x01};
    public static byte[] WRONG_LENGTH       = new byte[] {(byte)0x67,(byte)0x00};
    public static byte[] PROCESS_TEST     = new byte[] {(byte)0x90,(byte)0x08};

    public static byte[] AUTHENTICATION_OK     = new byte[] {(byte)0x90,(byte)0x01};
    public static byte[] AUTHENTICATION_FAILD     = new byte[] {(byte)0x90,(byte)0x02};
}
