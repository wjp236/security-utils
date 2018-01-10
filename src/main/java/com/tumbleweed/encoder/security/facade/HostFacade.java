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
 * 描述:服务端调用
 *
 * @author: mylover
 * @Time: 21/12/2017.
 */
public class HostFacade {


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
     * 响应Pos签到
     * @param skHost
     * @param pkPos
     * @return
     */
    public static Map<String, Object> reqPos(String skHost, String pkPos, String rndPosStr) throws Exception {

        Map<String, Object> ret = new HashMap<String, Object>();

        String rndHostStr = Ssc.generateString();

        ret.put("rndHost", rndHostStr);

        byte[] encodedData = RSACoder.encryptByPrivateKey(rndHostStr.getBytes(), skHost);
        String sign = RSACoder.sign(encodedData, skHost);

        ret.put("sign", sign);

        String key = Ssc.generateKey();
        ret.put("keyStr", key);

        byte[] encodedDataKey = RSACoder.encryptByPublicKey(key.getBytes(), pkPos);
        String tempStr = Base64Utils.encode(encodedDataKey);

        long ssc = Ssc.makeSsc(rndPosStr, rndHostStr);
        ret.put("ssc", ssc);

        ret.put("key", tempStr);
        ret.put("data", ByteUtil.bytesToHexString(encodedData));

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

        String data = new String(ByteUtil.convertHexString(body));

        //加密向量
        byte[] iv = ByteUtil.longToByteArray(ssc);

        byte[] macBytes = Pboc3Des.calculatePboc3desMAC(
                data.getBytes(), ByteUtil.bytesToHexString(key.getBytes()).getBytes(), iv);

        String mac = ByteUtil.toHexString(macBytes);

        mac = mac.substring(0, 4);

        Map<String, Object> ret = new HashMap<String, Object>();

        ret.put("mac", mac);
        ret.put("body", data);
        return ret;
    }

}
