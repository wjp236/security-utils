package com.tumbleweed.encoder.security.ssc.impl;

import com.tumbleweed.encoder.security.ssc.AbstractSsc;
import com.tumbleweed.encoder.security.utils.UUIDUitl;

/**
 * 描述:会话因子操作类
 *
 * @author: mylover
 * @Time: 21/12/2017.
 */
public class Ssc extends AbstractSsc {


    /**
     * 生成8位随机密钥
     * @return
     */
    public static String generateKey() {
        String key = UUIDUitl.generateString(8);
        return key;
    }

    /**
     * 生成8位全数字随机数
     * @return
     */
    public static String generateString() {
        return UUIDUitl.generateInteger(8);
    }


    /**
     * 计算会话因子
     * @param rndPosStr
     * @param rndHostStr
     */
    public static long makeSsc(String rndPosStr, String rndHostStr) {
        int rnd1 = Integer.parseInt(rndPosStr);
        int rnd2 = Integer.parseInt(rndHostStr);
        return rnd1 ^ rnd2;
    }
}
