package com.tumbleweed.encoder.security.hash;


/**
 * 抽象hash算法
 */
public abstract class AbstractHash {


    public abstract byte[] encrypt(byte[] data) throws Exception;

}
