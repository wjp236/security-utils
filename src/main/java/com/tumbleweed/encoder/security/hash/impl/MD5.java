package com.tumbleweed.encoder.security.hash.impl;


import com.tumbleweed.encoder.security.hash.AbstractHash;
import com.tumbleweed.encoder.security.utils.Common;

import java.security.MessageDigest;


/**
 * Hash算法 MD5算法
 */
public class MD5 extends AbstractHash {

    /**
     *  MD5
     * @param data
     * @return
     * @throws Exception
     */
    public byte[] encrypt(byte[] data) throws Exception {
        MessageDigest md5 = MessageDigest.getInstance(Common.KEY_MD5);
        md5.update(data);
        return md5.digest();
    }
}
