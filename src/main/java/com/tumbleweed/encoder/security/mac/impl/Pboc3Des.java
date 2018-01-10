package com.tumbleweed.encoder.security.mac.impl;

import com.tumbleweed.encoder.security.utils.DesUtils;

/**
 * 描述: PBOC_3DES_MAC标准算法
 *
 * @author: wangjp
 * @Time: 21/12/2017.
 */
public class Pboc3Des {


    public static final byte[] ZERO_IVC = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };
    /**
     * 计算MAC(hex) PBOC_3DES_MAC(符合ISO9797Alg3Mac标准)
     * (16的整数补8000000000000000) 前n-1组使用单长密钥DES 使用密钥是密钥的左8字节） 最后1组使用双长密钥3DES （使用全部16字节密钥）
     * 算法步骤：初始数据为D，初始向量为I，3DES秘钥为K0，秘钥低8字节DES秘钥K1；
     * 1、数据D分组并且填充：将字节数组D进行分组，每组8个字节，分组编号从0开始,分别为D0...Dn；最后一个分组不满8字节的，先填充一个字节80，后续全部填充00，满8字节的，新增一个8字节分组（80000000 00000000）；
     * 2、进行des循环加密：（1）D0和初始向量I进行按位异或得到结果O0;(2)使用秘钥K1，DES加密结果O0得到结果I1,将I1和D1按位异或得到结果D1；(3)循环第二步骤得到结果Dn；
     * 3、将Dn使用16字节秘钥K0进行3DES加密，得到的结果就是我们要的MAC。
     * @param data 带计算的数据
     * @param key 16字节密钥
     * @param icv 算法向量
     * @return mac签名
     * @throws Exception
     */
    public static byte[] calculatePboc3desMAC(byte[] data, byte[] key, byte[] icv) throws Exception {
        if (key == null || data == null)
            throw new RuntimeException("data or key is null.");
        if(key.length != 16)
            throw new RuntimeException("key length is not 16 byte.");

        byte[] leftKey = new byte[8];
        System.arraycopy(key, 0, leftKey, 0, 8);

        // 拆分数据（8字节块/Block）
        final int dataLength = data.length;
        final int blockCount = dataLength / 8 + 1;
        final int lastBlockLength = dataLength % 8;

        byte[][] dataBlock = new byte[blockCount][8];
        for (int i = 0; i < blockCount; i++) {
            int copyLength = i == blockCount - 1 ? lastBlockLength : 8;
            System.arraycopy(data, i * 8, dataBlock[i], 0, copyLength);
        }
        dataBlock[blockCount - 1][lastBlockLength] = (byte) 0x80;

        byte[] desXor = DesUtils.xOr(dataBlock[0], icv);
        for (int i = 1; i < blockCount; i++) {
            byte[] des = DesUtils.encryptByDesCbc(desXor, leftKey);
            desXor = DesUtils.xOr(dataBlock[i], des);
        }
        desXor = DesUtils.encryptBy3DesCbc(desXor, key);
        return desXor;
    }

}
