package server;

import core.CryptoProtocol;
import core.RSAUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;

import javax.crypto.SecretKey;

public class ClientHandler extends Thread {

	private final Socket socket;

	private static final KeyPair SERVER_KEYS;

	static {
		try {
			SERVER_KEYS = RSAUtil.generateKeyPair();
		} catch (Exception e) {
			throw new RuntimeException("Failed to generate server RSA keys", e);
		}
	}

	// Client's session AES key
	private SecretKey sessionKey;

	public ClientHandler(Socket socket) {
		this.socket = socket;
	}

	@Override
	public void run() {
		try (BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

			String pubB64 = RSAUtil.publicKeyToBase64(SERVER_KEYS.getPublic());
			out.println(CryptoProtocol.PUBLIC_KEY + CryptoProtocol.SEP + pubB64);

			String line = in.readLine();
			if (line == null) {
				System.out.println("Client disconnected during handshake.");
				return;
			}

			// AES_KEY|<rsaEncryptedAesKey>

			String[] parts = line.split("\\|", 2);
			if (parts.length != 2 || !CryptoProtocol.AES_KEY.equals(parts[0])) {
				System.out.println("Invalid handshake message: " + line);
				return;
			}

			String encryptedAesKeyB64 = parts[1];

			// Decrypt the AES key with the RSA private key
			String aesKeyBase64 = RSAUtil.decryptFromBase64(encryptedAesKeyB64, SERVER_KEYS.getPrivate());

			System.out.println("Handshake complete. AES key (base64) received: "
					+ aesKeyBase64.substring(0, Math.min(20, aesKeyBase64.length())) + "...");

			out.println("HANDSHAKE_OK");

		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				socket.close();
			} catch (Exception ignore) {
			}
		}
	}
}
