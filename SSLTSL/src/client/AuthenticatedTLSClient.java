package client;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;

public class AuthenticatedTLSClient {

    private static final String KEYSTORE_PATH = "client_keystore.p12";
    private static final String TRUSTSTORE_PATH = "truststore.jks";
    private static final String KEYSTORE_PASSWORD = "supersecret123";
    private static final String TRUSTSTORE_PASSWORD = "supersecret123";

    static void main(String[] args) {
        // Allow hostname to be passed as argument, default to localhost
        String hostname = args.length > 0 ? args[0] : "localhost";
        String urlString = "https://" + hostname + ":8443/";
        String outputFile = "authenticated_response.txt";

        try {

            System.out.println("Target: " + urlString);
            System.out.println("Client Certificate: " + KEYSTORE_PATH);
            System.out.println("Trusted CAs: " + TRUSTSTORE_PATH);

            // Load the client keystore (contains client certificate and private key)
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream keystoreStream = new FileInputStream(KEYSTORE_PATH);
            keyStore.load(keystoreStream, KEYSTORE_PASSWORD.toCharArray());
            keystoreStream.close();

            // Initialize KeyManagerFactory with client keystore
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

            System.out.println("✓ Client certificate loaded successfully");

            // Load the truststore (contains RootCA to verify server certificate)
            KeyStore trustStore = KeyStore.getInstance("JKS");
            FileInputStream truststoreStream = new FileInputStream(TRUSTSTORE_PATH);
            trustStore.load(truststoreStream, TRUSTSTORE_PASSWORD.toCharArray());
            truststoreStream.close();

            // Initialize TrustManagerFactory with truststore
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);

            System.out.println("✓ Truststore loaded successfully");

            // Initialize SSL context with both key managers and trust managers
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

            // For localhost/hostname testing, we need to allow hostname mismatch
            HttpsURLConnection.setDefaultHostnameVerifier((hostname1, session) -> {
                System.out.println("\n>>> Verifying hostname: " + hostname1);
                return true;
            });

            System.out.println("\n>>> Connecting to server");

            // Create the URL and open the HTTPS connection
            URL url = new URL(urlString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "AuthenticatedTLSClient/1.0");

            connection.connect();

            System.out.println("SSL Handshake successful!");
            System.out.println("Client certificate presented to server");

            // Get server certificates
            Certificate[] serverCerts = connection.getServerCertificates();

            System.out.println("\n========== Connection Details ==========");
            System.out.println("Response Code: " + connection.getResponseCode());
            System.out.println("Cipher Suite: " + connection.getCipherSuite());

            System.out.println("\n========== Server Certificate ==========");
            if (serverCerts.length > 0 && serverCerts[0] instanceof X509Certificate cert) {
                System.out.println("Subject: " + cert.getSubjectX500Principal().getName());
                System.out.println("Issuer: " + cert.getIssuerX500Principal().getName());

                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                System.out.println("Valid From: " + dateFormat.format(cert.getNotBefore()));
                System.out.println("Valid Until: " + dateFormat.format(cert.getNotAfter()));

                System.out.println("Public Key Algorithm: " + cert.getPublicKey().getAlgorithm());
                System.out.println("Signature Algorithm: " + cert.getSigAlgName());
            }

            // Read and save response
            System.out.println("\n>>> Reading response...");

            BufferedReader in = new BufferedReader(
                new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8)
            );

            BufferedWriter writer = new BufferedWriter(
                new FileWriter(outputFile)
            );

            String inputLine;
            int lineCount = 0;
            while ((inputLine = in.readLine()) != null) {
                writer.write(inputLine);
                writer.newLine();
                lineCount++;
            }

            in.close();
            writer.close();
            connection.disconnect();

            System.out.println("Response saved to: " + outputFile + " (" + lineCount + " lines)");
            System.out.println("\n========================================");
            System.out.println(" Connection successful!");
            System.out.println("Mutual TLS authentication completed");
            System.out.println("========================================");

        } catch (javax.net.ssl.SSLHandshakeException e) {
            System.err.println("\n========================================");
            System.err.println("SSL HANDSHAKE FAILED!");
            System.err.println("========================================");
            System.err.println("Error: " + e.getMessage());
            System.err.println("\nPossible reasons:");
            System.err.println("Server rejected client certificate");
            System.err.println("Client certificate not signed by trusted CA");
            System.err.println("Server certificate not trusted");
            System.err.println("========================================");
        } catch (Exception e) {
            System.err.println("CONNECTION FAILED!");
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
