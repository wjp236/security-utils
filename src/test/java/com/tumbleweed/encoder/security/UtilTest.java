package com.tumbleweed.encoder.security;

import com.tumbleweed.encoder.security.hash.AbstractHash;
import com.tumbleweed.encoder.security.hash.impl.MD5;
import com.tumbleweed.encoder.security.hash.impl.SHA1;
import com.tumbleweed.encoder.security.kpi.impl.RSACoder;
import com.tumbleweed.encoder.security.mac.impl.Pboc3Des;
import com.tumbleweed.encoder.security.ssc.impl.Ssc;
import com.tumbleweed.encoder.security.utils.Base64Utils;
import com.tumbleweed.encoder.security.utils.ByteUtil;
import org.junit.Test;

import java.util.Map;

/**
 * 描述: 算法测试
 *
 * @author: mylover
 * @Time: 19/12/2017.
 */
public class UtilTest {

    private String body = "thisIsBody123456";

    //公钥
    private static String pk = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCRi7CdW3UaI0pUfrwbClXOFKzsHuJKhNcYJM9R\n" +
            "sp9IpMZ+d+dXw5NZMpHTQtAvSE1G1pSdqEUcvDtPrw2I7SKL51NzMafcVJACZG4acuQJpvbHV+rm\n" +
            "+ymfkkk6/PN5scfXdUubcbYNztx60zqCEbxkse9wis6JkGReouwpaIXNjwIDAQAB";

    //私钥
    private static String sk = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAJGLsJ1bdRojSlR+vBsKVc4UrOwe\n" +
            "4kqE1xgkz1Gyn0ikxn5351fDk1kykdNC0C9ITUbWlJ2oRRy8O0+vDYjtIovnU3Mxp9xUkAJkbhpy\n" +
            "5Amm9sdX6ub7KZ+SSTr883mxx9d1S5txtg3O3HrTOoIRvGSx73CKzomQZF6i7Clohc2PAgMBAAEC\n" +
            "gYAJDwe0E5ArS00CC01L5Y3HoNPOcnGlL7VvhEL/E74EOHU+Q9o7RSnzoEkhPARXHQnqQcrIMUPz\n" +
            "8OdEI2IVRqUitfQJ0rXZtzYODXsn1m7M5HY4vJwPc0tyW5RI1OlAZHlIaZGGpPBlDIS8L3dH1cjk\n" +
            "8kMvJSRlyvOLeVtWlJ2AOQJBAM3qw7n8wsohwfQAr9R9MNe0K2nHZ4fZMZMo9hhQXp+i9C2KRj7J\n" +
            "dFTfqEJOysKVb1j7Q0eHQ7GQPFF+RN1RiWMCQQC08fTldPk3GWILjukbYW3Za5RItvsxG7uRIR85\n" +
            "e+yVJUWCgL0p8m/fK8kzwUVlEpP/AoX8UzOV0ShZaWC/6vjlAkAYwxeAYSXnesHBHugGDHv4JIFn\n" +
            "+gO4MWUlxjI54EhQuB7W7x7dZApqPm8UcjctyRyXvbdsfZalXqvyPNX5K1nzAkEAir5slfUXkxQ3\n" +
            "hb1TKNeQL4K59Pe5rHIjZKkNFDrdsY8euW6VnbBz75/Xa4Pq/hE8wfDhZBU4HMyAL+8JbJ9zsQJB\n" +
            "AMDXp9mzKj2UIuXSbkC/7VKlcP6jiUU3Z9Te5W9zxVyEzz9VNhDoI8k01P6j4G1RVN9acODHxNM6\n" +
            "c4mo+bc8lh0=";


    /**
     * 公私钥初始化
     * @throws Exception
     */
    @Test
    public void test0() throws Exception {
        Map<String, String> keyMap = RSACoder.initKey();
        System.out.println(RSACoder.PUBLIC_KEY + ":" + keyMap.get(RSACoder.PUBLIC_KEY));
        System.out.println(RSACoder.PRIVATE_KEY + ":" + keyMap.get(RSACoder.PRIVATE_KEY));
    }

    /**
     * 测试 公钥加密，私钥解密
     */
    @Test
    public void test1() throws Exception {
        System.out.println("公钥加密前包体:" + body);

        byte[] encodedData = RSACoder.encryptByPublicKey(body.getBytes(), pk);
        String tempStr = Base64Utils.encode(encodedData);
        System.err.println("传输公钥加密后包体: " + tempStr);

        byte[] tempByte = Base64Utils.decode(tempStr);
        byte[] decodedData = RSACoder.decryptByPrivateKey(tempByte, sk);
        System.err.println("解密后包体: " + new String(decodedData));
    }

    /**
     * 测试 私钥加密，公钥解密
     */
    @Test
    public void test2() throws Exception {
        System.out.println("私钥加密前包体:" + body);

        byte[] encodedData = RSACoder.encryptByPrivateKey(body.getBytes(), sk);
        String tempStr = Base64Utils.encode(encodedData);
        System.err.println("传输私钥加密后包体: " + tempStr);

        byte[] tempByte = Base64Utils.decode(tempStr);
        byte[] decodedData = RSACoder.decryptByPublicKey(tempByte, pk);
        System.err.println("解密后包体: " + new String(decodedData));
    }

    /**
     * 测试 私钥签名，公钥验证签名
     */
    @Test
    public void test3() throws Exception {
        System.out.println("私钥加密前包体:" + body);

        byte[] encodedData = RSACoder.encryptByPrivateKey(body.getBytes(), sk);

        String sign = RSACoder.sign(encodedData, sk);
        System.err.println("产生的签名:\r" + sign);

        String temp = ByteUtil.bytesToHexString(encodedData);

        byte[] tempB = ByteUtil.convertHexString(temp);

        // 验证签名
        boolean status = RSACoder.verify(tempB, pk, sign);
        System.err.println("状态:\r" + status);
    }

    /**
     * 测试 会话因子
     */
    @Test
    public void test4() {
        String rndPosStr = Ssc.generateString();
        System.out.println("POS生成的八位随机数:" + rndPosStr);

        String rndHostStr = Ssc.generateString();
        System.out.println("Host生成的八位随机数:" + rndHostStr);

        long ssc = Ssc.makeSsc(rndPosStr, rndHostStr);
        System.out.println("会话因子:" + ssc);
    }

    /**
     * 测试hash算法
     */
    @Test
    public void test5() throws Exception {
        System.out.println("加密前包体:" + body);

        AbstractHash md5 = new MD5();
        System.out.println(Base64Utils.encode(md5.encrypt(body.getBytes())));

        AbstractHash sha1 = new SHA1();
        System.out.println(Base64Utils.encode(sha1.encrypt(body.getBytes())));
    }

    /**
     * 测试mac算法
     */
    @Test
    public void test6() throws Exception {
        System.out.println("加密前包体:" + body);

        String rndPosStr = Ssc.generateString();
        System.out.println("POS生成的八位随机数:" + rndPosStr);

        String rndHostStr = Ssc.generateString();
        System.out.println("Host生成的八位随机数:" + rndHostStr);

        long ssc = Ssc.makeSsc(rndPosStr, rndHostStr);
        System.out.println("会话因子:" + ssc);

        //加密向量
        byte[] iv = ByteUtil.longToByteArray(ssc);

        String key = Ssc.generateKey();
        System.out.println("随机过程密钥:" + key);

        byte[] macBytes = Pboc3Des.calculatePboc3desMAC(
                body.getBytes(), ByteUtil.bytesToHexString(key.getBytes()).getBytes(), iv);

        String mac = ByteUtil.toHexString(macBytes);
        mac = mac.substring(0, 4);

        System.out.println("计算后的mac值:" + mac);
    }


}
