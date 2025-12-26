package client;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.List;
import java.security.SecureRandom;

public class TLSClient {

    static void main() {
        String urlString = "https://bnr.ro/Home.aspx";
        String outputFile = "bnr_response.txt";

        try {
            // Create a trust manager that accepts all certificates (JDK 25 does not trust BNR certificates)
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                    }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                    }
                }
            };

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Create a hostname verifier that accepts all hostnames
            HostnameVerifier allHostsValid = (hostname, session) -> true;
            HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);

            // Create the URL and open the HTTPS connection
            URL url = new URL(urlString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            // Set up the connection
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "Mozilla/5.0");

            // Connect
            connection.connect();

            // Get server certificates
            Certificate[] serverCerts = connection.getServerCertificates();

            System.out.println("Connected to: " + urlString);
            System.out.println("Response: " + connection.getResponseCode());
            System.out.println("Cipher Suite: " + connection.getCipherSuite());
            System.out.println("\n========== Certificates ==========\n");

            // Write out certificate information
            for (int i = 0; i < serverCerts.length; i++) {
                if (serverCerts[i] instanceof X509Certificate cert) {

                    System.out.println("Certificate #" + (i + 1) + ":");
                    System.out.println("-".repeat(50));

                    System.out.println("Version: " + cert.getVersion());

                    System.out.println("Serial Number: " + cert.getSerialNumber().toString(16).toUpperCase());

                    System.out.println("Issuer (CA): " + cert.getIssuerX500Principal().getName());

                    SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                    System.out.println("Valid From: " + dateFormat.format(cert.getNotBefore()));

                    System.out.println("Valid Until: " + dateFormat.format(cert.getNotAfter()));

                    System.out.println("Subject: " + cert.getSubjectX500Principal().getName());

                    try {
                        Collection<List<?>> san = cert.getSubjectAlternativeNames();
                        if (san != null) {
                            System.out.println("Subject Alternative Names:");
                            for (List<?> entry : san) {
                                Integer type = (Integer) entry.get(0);
                                String value = (String) entry.get(1);
                                switch (type) {
                                    case 2: // DNS name
                                        System.out.println("  DNS: " + value);
                                        break;
                                    case 7: // IP address
                                        System.out.println("  IP: " + value);
                                        break;
                                    default:
                                        System.out.println("  Type " + type + ": " + value);
                                }
                            }
                        }
                    } catch (Exception e) {
                        System.out.println("Subject Alternative Names: N/A");
                    }

                    System.out.println("Public Key Algorithm: " + cert.getPublicKey().getAlgorithm());
                    System.out.println("Public Key Format: " + cert.getPublicKey().getFormat());

                    byte[] publicKeyBytes = cert.getPublicKey().getEncoded();
                    System.out.println("Public Key (first 32 bytes): " + bytesToHex(publicKeyBytes));

                    System.out.println("Signature Algorithm: " + cert.getSigAlgName());

                    System.out.println();
                }
            }

            BufferedReader in = new BufferedReader(
                new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8)
            );

            BufferedWriter writer = new BufferedWriter(
                new FileWriter(outputFile)
            );

            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                writer.write(inputLine);
                writer.newLine();
            }

            in.close();
            writer.close();
            connection.disconnect();

            System.out.println("Response saved to: " + outputFile);
            System.out.println("\nConnection closed successfully.");

        } catch (Exception e) {
            System.err.println("Error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }


    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        int limit = Math.min(bytes.length, 32);
        for (int i = 0; i < limit; i++) {
            sb.append(String.format("%02X", bytes[i]));
            if (i < limit - 1 && (i + 1) % 16 == 0) {
                sb.append("\n  ");
            } else if (i < limit - 1) {
                sb.append(" ");
            }
        }
        return sb.toString();
    }
}
