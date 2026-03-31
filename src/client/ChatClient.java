package client;

import core.AESUtil;
import core.CryptoProtocol;
import core.RSAUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class ChatClient {

	private static final String HOST = "127.0.0.1";
	private static final int PORT = 5555;

	public static void main(String[] args) {
		System.out.println("ChatClient connecting to " + HOST + ":" + PORT + "...");

		try (Socket socket = new Socket(HOST, PORT);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

			// Server PUBLIC_KEY|<base64>
			String line = in.readLine();
			if (line == null) {
				System.out.println("Server closed connection.");
				return;
			}

			String[] parts = line.split("\\|", 2);
			if (parts.length != 2 || !CryptoProtocol.PUBLIC_KEY.equals(parts[0])) {
				System.out.println("Unexpected server message: " + line);
				return;
			}

			String serverPubB64 = parts[1];
			PublicKey serverPublicKey = RSAUtil.base64ToPublicKey(serverPubB64);

			System.out.println("Server public key received (first40): "
					+ serverPubB64.substring(0, Math.min(40, serverPubB64.length())) + "...");

			SecretKey aesKey = AESUtil.generateKey();
			String aesKeyB64 = AESUtil.keyToBase64(aesKey);

			String encryptedAesKeyB64 = RSAUtil.encryptToBase64(aesKeyB64, serverPublicKey);

			// AES_KEY|<rsaEncryptedBase64>
			out.println(CryptoProtocol.AES_KEY + CryptoProtocol.SEP + encryptedAesKeyB64);

			System.out.println("AES key generated + encrypted and sent.");

			String ack = in.readLine();
			System.out.println("Server says: " + ack);

			System.out.println("Handshake finished. (Next: send/receive AES encrypted messages)");

			String plainMessage = "Hello server, this is my first AES message!";
			String encryptedMessage = AESUtil.encrypt(plainMessage, aesKey);

			// MSG|<encryptedPayload>
			out.println(CryptoProtocol.MSG + CryptoProtocol.SEP + encryptedMessage);

			System.out.println("Plain message encrypted and sent.");
			System.out.println("Plain     : " + plainMessage);
			System.out.println("Encrypted : " + encryptedMessage);

			// Server reply
			String encryptedReplyLine = in.readLine();
			if (encryptedReplyLine == null) {
				System.out.println("Server closed connection before sending reply.");
				return;
			}

			String[] replyParts = encryptedReplyLine.split("\\|", 2);
			if (replyParts.length != 2 || !CryptoProtocol.MSG.equals(replyParts[0])) {
				System.out.println("Invalid reply format: " + encryptedReplyLine);
				return;
			}

			String encryptedReplyPayload = replyParts[1];
			String decryptedReply = AESUtil.decrypt(encryptedReplyPayload, aesKey);

			System.out.println("Server reply (encrypted): " + encryptedReplyPayload);
			System.out.println("Server reply (plain)    : " + decryptedReply);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}