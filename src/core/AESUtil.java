package core;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class AESUtil {

	private AESUtil() {
	}

	private static final String AES_ALGORITHM = "AES";
	private static final String AES_TRANSFORMATION = "AES/GCM/NoPadding";
	private static final int GCM_TAG_LENGTH_BITS = 128;
	private static final int IV_LENGTH_BYTES = 12;

	
	public static SecretKey generateKey() throws Exception {
		KeyGenerator kg = KeyGenerator.getInstance(AES_ALGORITHM);
		kg.init(256);
		return kg.generateKey();
	}

	
	public static String keyToBase64(SecretKey key) {
		return Base64.getEncoder().encodeToString(key.getEncoded());
	}

	
	public static SecretKey base64ToKey(String base64Key) {
		byte[] keyBytes = Base64.getDecoder().decode(base64Key);
		return new SecretKeySpec(keyBytes, AES_ALGORITHM);
	}
	
	
	public static String encrypt(String plainText, SecretKey key) throws Exception {
		byte[] iv = new byte[IV_LENGTH_BYTES];
		SecureRandom random = new SecureRandom();
		random.nextBytes(iv);

		Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
		GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
		cipher.init(Cipher.ENCRYPT_MODE, key, spec);

		byte[] cipherBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

		String ivB64 = Base64.getEncoder().encodeToString(iv);
		String ctB64 = Base64.getEncoder().encodeToString(cipherBytes);
		return ivB64 + ":" + ctB64;
	}
	
	
	public static String decrypt(String encrypted, SecretKey key) throws Exception {
		String[] parts = encrypted.split(":", 2);
		if (parts.length != 2) {
			throw new IllegalArgumentException("Invalid encrypted payload format. Expected iv:ciphertext");
		}

		byte[] iv = Base64.getDecoder().decode(parts[0]);
		byte[] cipherBytes = Base64.getDecoder().decode(parts[1]);

		Cipher cipher = Cipher.getInstance(AES_TRANSFORMATION);
		GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
		cipher.init(Cipher.DECRYPT_MODE, key, spec);

		byte[] plainBytes = cipher.doFinal(cipherBytes);
		return new String(plainBytes, StandardCharsets.UTF_8);
	}
}
