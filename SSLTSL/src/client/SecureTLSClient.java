package client;

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.List;

public class SecureTLSClient {

    static void main(String[] args) {
        String urlString = "https://bnr.ro/Home.aspx";
        String outputFile = "bnr_response_secure.txt";

        try {
            // Create a custom trust manager that detects self-signed certificates
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((java.security.KeyStore) null); // Use default Java truststore

            TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    private final X509TrustManager originalTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return originalTrustManager.getAcceptedIssuers();
                    }

                    @Override
                    public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        originalTrustManager.checkClientTrusted(certs, authType);
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                        if (certs == null || certs.length == 0) {
                            throw new CertificateException("No server certificates provided!");
                        }

                        X509Certificate serverCert = certs[0];

                        System.out.println("Validating certificate for: " + serverCert.getSubjectX500Principal().getName());

                        boolean isSelfSigned = serverCert.getIssuerX500Principal().equals(serverCert.getSubjectX500Principal());

                        if (isSelfSigned) {
                            System.err.println("\nWARNING: SELF-SIGNED CERTIFICATE DETECTED!");
                            System.err.println("Issuer: " + serverCert.getIssuerX500Principal().getName());
                            System.err.println("Subject: " + serverCert.getSubjectX500Principal().getName());
                            throw new CertificateException("Self-signed certificate detected! This is NOT the real BNR server!");
                        }

                        // Validate against Java's default trusted certificates
                        try {
                            originalTrustManager.checkServerTrusted(certs, authType);

                            System.out.println("Certificate validation successful!");
                            System.out.println("Certificate is trusted by a recognized Certificate Authority");

                        } catch (CertificateException e) {
                            System.err.println("\nCERTIFICATE VALIDATION FAILED!");
                            System.err.println("Reason: " + e.getMessage());
                            throw e;
                        }
                    }
                }
            };

            // Initialize SSL context
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> {
                System.out.println("Expected hostname: " + hostname);
                System.out.println("Certificate hostname: " + session.getPeerHost());

                try {
                    Certificate[] certs = session.getPeerCertificates();
                    if (certs.length > 0 && certs[0] instanceof X509Certificate) {
                        X509Certificate cert = (X509Certificate) certs[0];

                        // Check CN
                        String cn = cert.getSubjectX500Principal().getName();
                        System.out.println("Certificate CN: " + cn);

                        // Check SANs
                        Collection<List<?>> sans = cert.getSubjectAlternativeNames();
                        if (sans != null) {
                            System.out.println("Subject Alternative Names:");
                            for (List<?> san : sans) {
                                if (san.get(0).equals(2)) { // DNS name
                                    String dnsName = (String) san.get(1);
                                    System.out.println("  DNS: " + dnsName);
                                    if (hostname.equalsIgnoreCase(dnsName) ||
                                        dnsName.equals("*." + hostname) ||
                                        (dnsName.startsWith("*.") && hostname.endsWith(dnsName.substring(1)))) {
                                        System.out.println("Hostname verification successful!");
                                        return true;
                                    }
                                }
                            }
                        }

                        // Check if CN matches
                        if (cn.contains("CN=" + hostname)) {
                            System.out.println("Hostname verification successful!");
                            return true;
                        }
                    }

                    System.err.println("Hostname verification failed!");
                    return false;

                } catch (Exception e) {
                    System.err.println("Error during hostname verification: " + e.getMessage());
                    return false;
                }
            });

            // Create the URL and open the HTTPS connection
            URL url = new URL(urlString);
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            // Set up the connection
            connection.setRequestMethod("GET");
            connection.setRequestProperty("User-Agent", "Mozilla/5.0");

            System.out.println("\nConnecting to: " + urlString);
            connection.connect();

            // Get server certificates
            Certificate[] serverCerts = connection.getServerCertificates();

            System.out.println("\nConnected successfully!");
            System.out.println("Response Code: " + connection.getResponseCode());
            System.out.println("Cipher Suite: " + connection.getCipherSuite());

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
                    System.out.println("Signature Algorithm: " + cert.getSigAlgName());
                    System.out.println();
                }
            }

            // Read and save response
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
            System.out.println("\nConnection closed successfully. This is the REAL BNR server!");

        } catch (javax.net.ssl.SSLHandshakeException e) {
            System.err.println("This is NOT the real BNR server!");
            System.err.println("Possible MAN-IN-THE-MIDDLE attack detected!");
            System.err.println("Error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("\nCONNECTION FAILED!");
            System.err.println("Error: " + e.getMessage());
        }
    }
}
