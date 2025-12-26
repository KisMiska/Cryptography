package server;

import javax.net.ssl.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;

public class AuthenticatedTLSServer {

    private static final int PORT = 8443;
    private static final String KEYSTORE_PATH = "server_keystore.p12";
    private static final String TRUSTSTORE_PATH = "truststore.jks";
    private static final String KEYSTORE_PASSWORD = "supersecret123";
    private static final String TRUSTSTORE_PASSWORD = "supersecret123";
    private static final String RESPONSE_FILE = "bnr_response.txt";

    static void main() {
        try {
            // Load the server keystore (contains server certificate and private key)
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream keystoreStream = new FileInputStream(KEYSTORE_PATH);
            keyStore.load(keystoreStream, KEYSTORE_PASSWORD.toCharArray());
            keystoreStream.close();

            // Initialize KeyManagerFactory with server keystore
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            // Load the truststore (contains RootCA to verify client certificates)
            KeyStore trustStore = KeyStore.getInstance("JKS");
            FileInputStream truststoreStream = new FileInputStream(TRUSTSTORE_PATH);
            trustStore.load(truststoreStream, TRUSTSTORE_PASSWORD.toCharArray());
            truststoreStream.close();

            // Initialize TrustManagerFactory with truststore
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            // Initialize SSL context with both key managers and trust managers
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            // Create SSL server socket
            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(PORT);

            // Require client authentication
            serverSocket.setNeedClientAuth(true);


            System.out.println("Port: " + PORT);
            System.out.println("Client Authentication: REQUIRED");
            System.out.println("Server Certificate: " + KEYSTORE_PATH);
            System.out.println("Trusted CA: " + TRUSTSTORE_PATH);
            System.out.println("Waiting for connections...");
            System.out.println();

            // Accept connections
            while (true) {
                try {
                    SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                    System.out.println("\n>>> New connection attempt from: " + clientSocket.getInetAddress());

                    // Handle client
                    new Thread(() -> handleClient(clientSocket)).start();

                } catch (Exception e) {
                    System.err.println(">>> Connection rejected: " + e.getMessage());
                    System.err.println("    Reason: Client does not have a valid certificate signed by ClientCA");
                    System.out.println();
                }
            }

        } catch (Exception e) {
            System.err.println("Server error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void handleClient(SSLSocket clientSocket) {
        try {
            // Get client certificate information
            System.out.println(">>> SSL Handshake successful!");

            try {
                var peerCertificates = clientSocket.getSession().getPeerCertificates();
                if (peerCertificates.length > 0) {
                    var clientCert = (java.security.cert.X509Certificate) peerCertificates[0];
                    System.out.println("    Client Certificate:");
                    System.out.println("    - Subject: " + clientCert.getSubjectX500Principal().getName());
                    System.out.println("    - Issuer: " + clientCert.getIssuerX500Principal().getName());
                    System.out.println("    - Valid Until: " + clientCert.getNotAfter());
                }
            } catch (Exception e) {
                System.out.println("    Could not retrieve client certificate details");
            }

            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            // Read the HTTP request
            String line;
            StringBuilder request = new StringBuilder();
            while ((line = in.readLine()) != null && !line.isEmpty()) {
                request.append(line).append("\n");
            }

            System.out.println("    Request received:");
            String[] requestLines = request.toString().split("\n");
            for (String reqLine : requestLines) {
                System.out.println("      " + reqLine);
            }

            // Read the HTML content from file
            String htmlContent;
            try {
                htmlContent = new String(Files.readAllBytes(Paths.get(RESPONSE_FILE)));
            } catch (IOException e) {
                htmlContent = "<html><body><h1>Authenticated TLS Server</h1><p>You have successfully authenticated with a client certificate!</p></body></html>";
                System.out.println("    Note: Could not read response file, using default content");
            }

            // Send HTTP response
            out.println("HTTP/1.1 200 OK");
            out.println("Content-Type: text/html; charset=UTF-8");
            out.println("Content-Length: " + htmlContent.getBytes().length);
            out.println("Connection: close");
            out.println();
            out.println(htmlContent);
            out.flush();

            System.out.println("    Response sent successfully");
            System.out.println(">>> Connection closed");
            System.out.println();

            clientSocket.close();

        } catch (Exception e) {
            System.err.println("    Error handling client: " + e.getMessage());
            try {
                clientSocket.close();
            } catch (IOException ex) {
            }
        }
    }
}
