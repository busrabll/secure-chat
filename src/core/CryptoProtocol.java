package core;

public final class CryptoProtocol {

	private CryptoProtocol() {
	}

	// Handshake
	public static final String HELLO = "HELLO_SERVER";
	public static final String PUBLIC_KEY = "SERVER_PUBLIC_KEY";
	public static final String AES_KEY = "AES_KEY";

	// Chat
	public static final String MSG = "MSG";
	public static final String SEP = "|";

}
