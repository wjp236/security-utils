package com.tumbleweed.encoder.security.des.impl;


import com.tumbleweed.encoder.security.des.AbstractDes;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class DESede extends AbstractDes {
	private byte[] keybyte;
	private String mode = "DESede/ECB/NoPadding";

	private DESede(byte[] key) {
		this.keybyte = key;
	}

	public static DESede newInstance24(byte[] key) {
		if ((key != null) && (key.length == 24)) {
			return new DESede(key);
		}
		System.err.println("密钥长度有误,期望值[24]");
		return null;
	}

	public static DESede newInstance16(byte[] key) {
		if ((key != null) && (key.length == 16)) {
			byte[] b = new byte[24];
			System.arraycopy(key, 0, b, 0, 16);
			System.arraycopy(key, 0, b, 16, 8);
			key = (byte[]) null;
			return new DESede(b);
		}
		System.err.println("密钥长度有误,期望值[16]");
		return null;
	}

	public static DESede newInstance8(byte[] key) {
		if ((key != null) && (key.length == 8)) {
			byte[] b = new byte[24];
			System.arraycopy(key, 0, b, 0, 8);
			System.arraycopy(key, 0, b, 8, 8);
			System.arraycopy(key, 0, b, 16, 8);
			key = (byte[]) null;
			return new DESede(b);
		}
		System.err.println("密钥长度有误,期望值[8]");
		return null;
	}

	public byte[] encrypt(byte[] src) {
		try {
			SecretKey deskey = new SecretKeySpec(this.keybyte, "DESede");

			Cipher c1 = Cipher.getInstance(this.mode);
			c1.init(1, deskey);
			return c1.doFinal(src);
		} catch (Exception e) {
			System.err.println(e);
		}
		return null;
	}

	public byte[] decrypt(byte[] src) {
		try {
			SecretKey deskey = new SecretKeySpec(this.keybyte, "DESede");

			Cipher c1 = Cipher.getInstance(this.mode);
			c1.init(2, deskey);
			return c1.doFinal(src);
		} catch (Exception e) {
			System.err.println(e);
		}
		return null;
	}

	public void setMode(String mode) {
		this.mode = mode;
	}
}
