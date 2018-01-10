package com.tumbleweed.encoder.security.hash.impl;


import com.tumbleweed.encoder.security.hash.AbstractHash;
import com.tumbleweed.encoder.security.utils.Common;

import java.security.MessageDigest;


/**
 * Hash算法 sha1算法
 */
public class SHA1 extends AbstractHash {

    /**
     * SHA加密
     *
     * @param data
     * @return
     * @throws Exception
     */
    public byte[] encrypt(byte[] data) throws Exception {
        MessageDigest sha = MessageDigest.getInstance(Common.KEY_SHA);
        sha.update(data);
        return sha.digest();
    }

}
