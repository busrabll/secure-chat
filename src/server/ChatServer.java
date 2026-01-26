package server;

import java.net.ServerSocket;
import java.net.Socket;

public class ChatServer {

	private static final int PORT = 5555;

	public static void main(String[] args) {

		System.out.println("ChatServer starting on port" + PORT + "...");

		// try-with-resources: When the server shuts down, the ServerSocket automatically closes
		try (ServerSocket serverSocket = new ServerSocket(PORT)) {

			// The server constantly waits for new clients
			while (true) {
				Socket clientSocket = serverSocket.accept();
				System.out.println("Client connected: " + clientSocket.getRemoteSocketAddress());

				ClientHandler handler = new ClientHandler(clientSocket);
				handler.start();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
