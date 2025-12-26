package server;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

public class FakeBNRServer {

    private static final int PORT = 443;
    private static final String KEYSTORE_PATH = "fake_bnr_keystore.p12";
    private static final String KEYSTORE_PASSWORD = "supersecret123";
    private static final String RESPONSE_FILE = "bnr_response.txt";

    static void main() {
        try {
            // Load the keystore containing the fake BNR certificate
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream keystoreStream = new FileInputStream(KEYSTORE_PATH);
            keyStore.load(keystoreStream, KEYSTORE_PASSWORD.toCharArray());
            keystoreStream.close();

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            // Initialize SSL context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);

            // Create SSL server socket
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(PORT);

            System.out.println("Fake BNR Server started on port " + PORT);
            System.out.println("Waiting for connections...");
            System.out.println();

            // Accept connections
            while (true) {
                try {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    System.out.println("Client connected from: " + clientSocket.getInetAddress());

                    // Handle incoming client
                    new Thread(() -> handleClient(clientSocket)).start();

                } catch (Exception e) {
                    System.err.println("Error accepting client: " + e.getMessage());
                }
            }

        } catch (Exception e) {
            System.err.println("Server error: " + e.getMessage());
        }
    }

    private static void handleClient(SSLSocket clientSocket) {
        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            // Read the HTTP request
            String line;
            StringBuilder request = new StringBuilder();
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                request.append(line).append("\n");
            }

            System.out.println("Received request:");
            System.out.println(request.toString());

            // Read content
            String htmlContent;
            try {
                htmlContent = new String(Files.readAllBytes(Paths.get(RESPONSE_FILE)));
            } catch (IOException e) {
                htmlContent = "<html><body><h1>Error: Could not read response file</h1></body></html>";
                System.err.println("Error reading response file: " + e.getMessage());
            }

            // Send HTTP response
            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: text/html; charset=UTF-8");
            out.println("Content-Length: " + htmlContent.getBytes().length);
            out.println("Connection: close");
            out.println();
            out.println(htmlContent);
            out.flush();

            System.out.println("Response sent to client");
            System.out.println();

            clientSocket.close();

        } catch (Exception e) {
            System.err.println("Error handling client: " + e.getMessage());
        }
    }
}
