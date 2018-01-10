package com.tumbleweed.encoder.security.mac.impl;


import com.tumbleweed.encoder.security.des.impl.Des;
import com.tumbleweed.encoder.security.exception.MacException;
import com.tumbleweed.encoder.security.mac.AbstractMac;
import com.tumbleweed.encoder.security.utils.ByteUtil;

public class ANSIX919 extends AbstractMac {
		
	private ANSIX99 ansix = new ANSIX99();
	
	@Override
	public byte[] getMac(byte[] src, byte[] tak) throws MacException {
		if(tak == null || tak.length != 16){
			throw new MacException("TAK长度错误[16]");
		}
		byte[] left = new byte[8];
		byte[] right = new byte[8];
		System.arraycopy(tak, 0, left, 0, 8);
		System.arraycopy(tak, 8, right, 0, 8);
		
		byte[] macTemp = ansix.getMac(src, left);
		System.out.println("macTemp="+ ByteUtil.bytesToHexString(macTemp));
		

		Des des2 = new Des(right);
		byte[] temp = des2.decrypt(macTemp);
		System.out.println("temp="+ByteUtil.bytesToHexString(temp));
		
		Des des1 = new Des(left);
		byte[] mac = des1.encrypt(temp);
		System.out.println("mac="+ByteUtil.bytesToHexString(mac));
		return mac;
	}

}
