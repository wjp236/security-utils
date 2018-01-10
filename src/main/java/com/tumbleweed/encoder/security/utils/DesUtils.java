package com.tumbleweed.encoder.security.utils;



import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 描述: des加解密工具类
 *
 * @author: mylover
 * @Time: 21/12/2017.
 */
public class DesUtils {


    public static final byte[] ZERO_IVC = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

    /**
     * 生成秘钥
     * @return 16字节3des秘钥
     * @throws GeneralSecurityException
     */
    public static byte[] create3DESKey() throws GeneralSecurityException {
        KeyGenerator kg = KeyGenerator.getInstance("DESede");
        kg.init(112);//must be equal to 112 or 168
        byte[] key24 =  kg.generateKey().getEncoded();
        byte[] result = new byte[16];
        System.arraycopy(key24, 0, result, 0, 16);
        return result;
    }

    /**
     * 3DES加密cbc模式
     * @param content 待加密数据
     * @param key 秘钥
     * @param ivb 向量
     * @return 加密结果
     * @throws GeneralSecurityException
     */
    public static byte[] encryptBy3DesCbc(byte[] content, byte[] key, byte[] ivb) throws GeneralSecurityException {
        byte[] _3deskey = new byte[24];
        System.arraycopy(key, 0, _3deskey, 0, 16);
        System.arraycopy(key, 0, _3deskey, 16, 8);

        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        SecretKey secureKey = new SecretKeySpec(_3deskey, "DESede");
        IvParameterSpec iv = new IvParameterSpec(ivb);
        cipher.init(Cipher.ENCRYPT_MODE, secureKey, iv);
        return cipher.doFinal(content);
    }
    /**
     * 3DES解密cbc模式
     * @param content 待解密数据
     * @param key 秘钥
     * @param ivb 向量
     * @return 解密结果
     * @throws GeneralSecurityException
     */
    public static byte[] decryptBy3DesCbc(byte[] content, byte[] key, byte[] ivb) throws GeneralSecurityException {
        byte[] _3deskey = new byte[24];
        System.arraycopy(key, 0, _3deskey, 0, 16);
        System.arraycopy(key, 0, _3deskey, 16, 8);

        Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
        SecretKey secureKey = new SecretKeySpec(_3deskey, "DESede");
        IvParameterSpec iv = new IvParameterSpec(ivb);
        cipher.init(Cipher.DECRYPT_MODE, secureKey, iv);
        return cipher.doFinal(content);
    }
    /**
     * 3DES加密cbc模式，默认向量
     * @param content 待加密数据
     * @param key 秘钥
     * @return 加密结果
     * @throws GeneralSecurityException
     */
    public static byte[] encryptBy3DesCbc(byte[] content, byte[] key) throws GeneralSecurityException {
        return encryptBy3DesCbc(content, key, ZERO_IVC);
    }

    /**
     * 3DES解密cbc模式，默认向量
     * @param content 带解密数据
     * @param key 秘钥
     * @return 解密结果
     * @throws GeneralSecurityException
     */
    public static byte[] decryptBy3DesCbc(byte[] content, byte[] key) throws GeneralSecurityException {
        return decryptBy3DesCbc(content, key, ZERO_IVC);
    }

    /**
     * 3DES加密Ecb模式
     * @param content 待加密数据
     * @param key 加密秘钥
     * @return 加密结果
     * @throws GeneralSecurityException
     */
    public static byte[] encryptBy3DesEcb(byte[] content, byte[] key) throws GeneralSecurityException {
        byte[] _3deskey = new byte[24];
        System.arraycopy(key, 0, _3deskey, 0, 16);
        System.arraycopy(key, 0, _3deskey, 16, 8);

        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        SecretKey secureKey = new SecretKeySpec(_3deskey, "DESede");
        cipher.init(Cipher.ENCRYPT_MODE, secureKey);
        return cipher.doFinal(content);
    }

    /**
     * 3DES解密Ecb模式
     * @param content 待解密数据
     * @param key 秘钥
     * @return 解密结果
     * @throws GeneralSecurityException
     */
    public static byte[] decryptBy3DesEcb(byte[] content, byte[] key) throws GeneralSecurityException {
        byte[] _3deskey = new byte[24];
        System.arraycopy(key, 0, _3deskey, 0, 16);
        System.arraycopy(key, 0, _3deskey, 16, 8);

        Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
        SecretKey secureKey = new SecretKeySpec(_3deskey, "DESede");
        cipher.init(Cipher.DECRYPT_MODE, secureKey);
        return cipher.doFinal(content);
    }

    /**
     * des的cbc模式加密算法
     * @param content 待加密数据
     * @param key 密钥
     * @return 加密结果
     * @throws GeneralSecurityException
     */
    public static byte[] encryptByDesCbc(byte[] content, byte[] key) throws GeneralSecurityException {
        return encryptByDesCbc(content, key, ZERO_IVC);
    }
    /**
     * des的cbc模式解密算法
     * @param content 待解密数据
     * @param key 密钥
     * @return 解密结果
     * @throws GeneralSecurityException
     */
    public static byte[] decryptByDesCbc(byte[] content, byte[] key) throws GeneralSecurityException {
        return decryptByDesCbc(content, key, ZERO_IVC);
    }

    /**
     * des的cbc模式加密算法
     * @param content 待加密数据
     * @param key 加密密钥
     * @return 加密结果
     * @throws GeneralSecurityException
     */
    public static byte[] encryptByDesCbc(byte[] content, byte[] key, byte[] icv) throws GeneralSecurityException {
        SecureRandom sr = new SecureRandom();
        DESKeySpec dks = new DESKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(dks);
        Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        IvParameterSpec iv = new IvParameterSpec(icv);

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv, sr);

        return cipher.doFinal(content);
    }

    /**
     * des的cbc模式解密算法
     * @param content 待解密数据
     * @param key 密钥
     * @return 解密结果
     * @throws GeneralSecurityException
     */
    public static byte[] decryptByDesCbc(byte[] content, byte[] key, byte[] icv) throws GeneralSecurityException {
        SecureRandom sr = new SecureRandom();
        DESKeySpec dks = new DESKeySpec(key);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(dks);
        Cipher cipher = Cipher.getInstance("DES/CBC/NoPadding");
        IvParameterSpec iv = new IvParameterSpec(icv);

        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv, sr);

        return cipher.doFinal(content);
    }

    /**
     * des加密算法，ECB方式，NoPadding模式，数据字节必须是8的整数倍
     * @param key
     * @param content 数据字节必须是8的整数倍
     * @return 加密结果
     * @throws GeneralSecurityException
     */
    public static byte[] encryptByDesEcb(byte[] content, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(new DESKeySpec(key));
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        return cipher.doFinal(content);
    }

    /**
     * des解密算法，ECB方式，NoPadding模式，数据字节必须是8的整数倍
     * @param key 秘钥
     * @param content 数据字节必须是8的整数倍
     * @throws GeneralSecurityException
     * @return
     */
    public static byte[] decryptByDesEcb(byte[] content, byte[] key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
        SecretKey secretKey = keyFactory.generateSecret(new DESKeySpec(key));
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        return cipher.doFinal(content);
    }

    /**
     * 本项目用于生成外部设备认证码和校验卡认证码（javacard GP规范 SCP02安全通道）（cardCryptogram）
     * B.1.2.1  Full Triple DES MAC
     * The full triple DES MAC is as defined in [ISO 9797-1] as MAC Algorithm 1 with output transformation 3,
     * without truncation, and with triple DES taking the place of the block cipher.
     * @param content 待加密数据
     * @param key 加密密钥
     * @return 加密结果后8字节
     * @throws Exception
     */
    public static byte[] encryptBy3DesCbcLast8Mac(byte[] content, byte[] key) throws GeneralSecurityException {
        byte[] edata = encryptBy3DesCbc(content, key);

        byte[] result = new byte[8];
        System.arraycopy(edata, edata.length - 8, result, 0, 8);
        return result;
    }
    /**
     * 将b1和b2做异或，然后返回
     * @param b1
     * @param b2
     * @return 异或结果
     */
    public static byte[] xOr(byte[] b1, byte[] b2) {
        byte[] tXor = new byte[Math.min(b1.length, b2.length)];
        for (int i = 0; i < tXor.length; i++)
            tXor[i] = (byte) (b1[i] ^ b2[i]); // 异或(Xor)
        return tXor;
    }

    /**
     * 整形转字节
     * @param n 整形数值
     * @param buf 结果字节数组
     * @param offset 填充开始位置
     */
    public static void int2byte(int n, byte buf[], int offset){
        buf[offset] = (byte)(n >> 24);
        buf[offset + 1] = (byte)(n >> 16);
        buf[offset + 2] = (byte)(n >> 8);
        buf[offset + 3] = (byte)n;
    }

    /**
     * 长整形转字节
     * @param n 长整形数值
     * @param buf 结果字节数组
     * @param offset 填充开始位置
     */
    public static void long2byte(long n, byte buf[], int offset){
        buf[offset] = (byte)(int)(n >> 56);
        buf[offset + 1] = (byte)(int)(n >> 48);
        buf[offset + 2] = (byte)(int)(n >> 40);
        buf[offset + 3] = (byte)(int)(n >> 32);
        buf[offset + 4] = (byte)(int)(n >> 24);
        buf[offset + 5] = (byte)(int)(n >> 16);
        buf[offset + 6] = (byte)(int)(n >> 8);
        buf[offset + 7] = (byte)(int)n;
    }

}
