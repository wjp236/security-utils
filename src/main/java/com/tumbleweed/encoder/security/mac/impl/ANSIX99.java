package com.tumbleweed.encoder.security.mac.impl;


import com.tumbleweed.encoder.security.des.impl.Des;
import com.tumbleweed.encoder.security.exception.MacException;
import com.tumbleweed.encoder.security.mac.AbstractMac;

public class ANSIX99 extends AbstractMac {

	public byte[] getMac(byte[] src, byte[] tak) throws MacException {
		if ((src == null) || (src.length == 0))
			throw new MacException("计算MAC的数据为空, src = " + src);
		if (tak == null)
			throw new MacException("TAK为空");
		if (tak.length != 8)
			throw new MacException("TAK的长度有误[" + tak.length + "],期望值[8]");
		try {
			src = getEightMultiplesData(src);
			int dataLen = src.length;
			int groupLen = dataLen / 8;
			byte[][] body = new byte[groupLen][8];
			int index = 0;
			for (int i = 0; i < groupLen; i++) {
				System.arraycopy(src, index, body[i], 0, 8);
				index += 8;
			}
			Des des = new Des(tak);
			byte[] zero = new byte[8];
			for (int i = 0; i < groupLen; i++) {
				zero = getExclusiveOR(body[i], zero);
				zero = des.encrypt(zero);
			}
			body = (byte[][]) null;
			return zero;
		} catch (Exception e) {
			System.err.println(e);
			throw new MacException("计算MAC出错,原因:" + e.getMessage());
		}
	}

}
