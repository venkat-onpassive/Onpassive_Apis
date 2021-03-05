package com.onpassive.omail.util;

import java.security.Key;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {

	private static final String SECRET_KEY = "ONPASSIVE#$%^&*(*&";

	private static final String ALGO = "AES"; // Default uses ECB PKCS5Padding

	public static String encrypt(String plainText) throws Exception {

		String encodedBase64Key = encodeKey(SECRET_KEY);
		Key key = generateKey(encodedBase64Key);
		Cipher c = Cipher.getInstance(ALGO);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encVal = c.doFinal(plainText.getBytes());
		String encryptedValue = Base64.getEncoder().encodeToString(encVal);
		return encryptedValue;
	}

	public static String decrypt(String encryptText) {

		try {
			String encodedBase64Key = encodeKey(SECRET_KEY);
			Key key = generateKey(encodedBase64Key);
			Cipher cipher = Cipher.getInstance(ALGO);
			cipher.init(Cipher.DECRYPT_MODE, key);
			return new String(cipher.doFinal(Base64.getDecoder().decode(encryptText)));
		} catch (Exception e) {
			System.out.println("Error while decrypting: " + e.toString());
		}
		return null;
	}

	private static Key generateKey(String secret) throws Exception {
		byte[] decoded = Base64.getDecoder().decode(secret.getBytes());
		Key key = new SecretKeySpec(decoded, ALGO);
		return key;
	}

	public static String encodeKey(String str) {
		byte[] encoded = Base64.getEncoder().encode(str.getBytes());
		return new String(encoded);
	}

}
