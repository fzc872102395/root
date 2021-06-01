package com.example.rsa.Utils;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

public class RSAUtils {
    public static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";

    private static Map<Integer, Key> keyMap = new HashMap<>();

    private void genKeyPair() throws Exception{
        // 创建基于RSA算法的KeyPairGenerator对象，用于随机生成RSA秘钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        //初始化该对象,设置秘钥长度为96-1024
        keyPairGenerator.initialize(1024,new SecureRandom());
        //存放秘钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        keyMap.put(0,privateKey);
        keyMap.put(1,publicKey);
    }

    //公钥加密
    public static byte[] encrypt(byte[] content, PublicKey publicKey){
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            return cipher.doFinal(content);
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static String encrypt(String content, PublicKey publicKey){
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] b = cipher.doFinal(content.getBytes());
            BASE64Encoder encoder = new BASE64Encoder();
            return encoder.encode(b);
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    //私钥解密
    public static byte[] decrypt(byte[] content, PrivateKey privateKey){
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(content);
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    public static String decrypt(String content, PrivateKey privateKey){
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            byte[] b = cipher.doFinal(content.getBytes());
            BASE64Encoder encoder = new BASE64Encoder();
            return encoder.encode(b);
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    //String转PublicKey
    public static PublicKey getPublicKey(String key){
        try {
            byte[] keyByte;
            keyByte = (new BASE64Decoder()).decodeBuffer(key);
            //初始化公钥
            //材料转换
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyByte);
            //实例化秘钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePublic(keySpec);
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

    //String转PrivateKey
    public static PrivateKey getPrivateKey(String key){
        try {
            byte[] keyByte;
            keyByte = (new BASE64Decoder()).decodeBuffer(key);
            //初始化私钥
            //材料转换
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyByte);
            //实例化秘钥工厂
            KeyFactory keyFactory = KeyFactory.getInstance(RSA_ALGORITHM);
            return keyFactory.generatePrivate(keySpec);
        }
        catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
}
