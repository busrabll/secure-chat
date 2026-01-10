package server;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public final class RSAUtil {

	private RSAUtil() {
	}

	// RSA algoritması ve dönüşüm
	private static final String RSA_TRANSFORMATION = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	public static KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		return kpg.generateKeyPair();
	}

	public static String publicKeyToBase64(PublicKey publicKey) {
		return Base64.getEncoder().encodeToString(publicKey.getEncoded());
	}

	public static PublicKey base64ToPublicKey(String base64) throws Exception {
		byte[] keyBytes = Base64.getDecoder().decode(base64);
		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
		return KeyFactory.getInstance("RSA").generatePublic(spec);
	}

	public static String encryptToBase64(String plainText, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);

		byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
		return Base64.getEncoder().encodeToString(encrypted);
	}

	public static String decryptFromBase64(String base64CipherText, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance(RSA_TRANSFORMATION);
		cipher.init(Cipher.DECRYPT_MODE, privateKey);

		byte[] cipherBytes = Base64.getDecoder().decode(base64CipherText);
		byte[] decrypted = cipher.doFinal(cipherBytes);
		return new String(decrypted, StandardCharsets.UTF_8);
	}
}
