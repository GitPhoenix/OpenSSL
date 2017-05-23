package com.alley.openssl.util;


public class JniUtils {

    static {
        System.loadLibrary("crypto");
        System.loadLibrary("signature");
    }

    public native byte[] getSignature(byte[] value);
}
