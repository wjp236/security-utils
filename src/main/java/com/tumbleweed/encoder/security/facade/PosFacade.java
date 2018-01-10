package com.tumbleweed.encoder.security.facade;

import com.tumbleweed.encoder.security.exception.KeyException;
import com.tumbleweed.encoder.security.kpi.impl.RSACoder;
import com.tumbleweed.encoder.security.mac.impl.Pboc3Des;
import com.tumbleweed.encoder.security.ssc.impl.Ssc;
import com.tumbleweed.encoder.security.utils.Base64Utils;
import com.tumbleweed.encoder.security.utils.ByteUtil;

import java.util.HashMap;
import java.util.Map;

/**
 * 描述: Pos外观调用
 *
 * @author: mylover
 * @Time: 21/12/2017.
 */
public class PosFacade {


    /**
     * 签到
     * @param sk pos终端私钥签名
     * @param prefix 前缀
     * @param sn sn号
     * @param rfu
     * @return
     */
    public static Map<String, Object> sign(String sk, String prefix, String sn, String rfu) throws Exception {

        String rndPosStr = Ssc.generateString();
        String data = prefix + sn + rfu + rndPosStr;
        System.out.println(data);

        byte[] encodedData = RSACoder.encryptByPrivateKey(data.getBytes(), sk);
        String sign = RSACoder.sign(encodedData, sk);

        Map<String, Object> ret = new HashMap<String, Object>();
        ret.put("rndPos", rndPosStr);
        ret.put("sign", sign);
        ret.put("sn", sn);
        ret.put("rfu", rfu);
        ret.put("data", ByteUtil.bytesToHexString(encodedData));
        return ret;
    }

    /**
     * 验证签名
     * @param pk
     * @param sign
     * @param data
     */
    public static void checkSign(String pk, String sign, String data) throws Exception {
        // 验证签名
        boolean status = RSACoder.verify(ByteUtil.convertHexString(data), pk, sign);
        System.err.println("状态:\r" + status);

        if (!status) {
            throw new KeyException("签名验证不通过");
        }

    }

    /**
     * 解密过程密钥，取得会话因子
     * @param skPos
     * @param key
     * @param rndHostStr
     * @param rndPosStr
     * @return
     * @throws Exception
     */
    public static Map<String, Object> makeKey(String skPos, String key, String rndHostStr, String rndPosStr) throws Exception {

        byte[] tempByte = Base64Utils.decode(key);
        byte[] decodedData = RSACoder.decryptByPrivateKey(tempByte, skPos);
        String decodeKey = new String(decodedData);

        Map<String, Object> ret = new HashMap<String, Object>();
        ret.put("key", decodeKey);

        long ssc = Ssc.makeSsc(rndPosStr, rndHostStr);
        ret.put("ssc", ssc);

        return ret;
    }

    /**
     * 计算mac
     * @param body
     * @param key
     * @param ssc
     * @return
     */
    public static Map<String, Object> mac(String body, String key, long ssc) throws Exception {
        //加密向量
        byte[] iv = ByteUtil.longToByteArray(ssc);

        byte[] macBytes = Pboc3Des.calculatePboc3desMAC(
                body.getBytes(), ByteUtil.bytesToHexString(key.getBytes()).getBytes(), iv);

        String mac = ByteUtil.toHexString(macBytes);

        mac = mac.substring(0, 4);

        System.out.println("计算后的mac值:" + mac);

        Map<String, Object> ret = new HashMap<String, Object>();

        String data = ByteUtil.bytesToHexString(body.getBytes());

        ret.put("mac", mac);
        ret.put("data", data);
        return ret;
    }
}
