package com.doan.server;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.json.JSONObject;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class ServerMain {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/verify", new VerifyHandler());
        server.setExecutor(null);
        System.out.println("🚀 Server running on http://localhost:8080/verify");
        server.start();
    }

    static class VerifyHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
                exchange.sendResponseHeaders(405, -1);
                return;
            }

            InputStream is = exchange.getRequestBody();
            String jsonStr = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            JSONObject json = new JSONObject(jsonStr);

            try {
                String rawMessage = json.getString("rawMessage");
                String signature = json.getString("signature");
                String clientPublicKey = json.getString("clientPublicKey");
                String encryptedAESKey = json.getString("encryptedAESKey");
                String encryptedMessage = json.getString("encryptedMessage");
                String ivBase64 = json.getString("iv");

                boolean isVerified = ServerVerifier.verifySignature(rawMessage, signature, clientPublicKey);

                if (!isVerified) {
                    String response = "VERIFICATION_FAILED";
                    exchange.sendResponseHeaders(403, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    return;
                }

                // Giải mã AES key và message
                PrivateKey privateKey = loadPrivateKey("keys/server_private.pem");
                SecretKey aesKey = ServerVerifier.decryptAESKey(encryptedAESKey, privateKey);
                IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(ivBase64));

                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, aesKey, iv);
                byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
                String decryptedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);

                System.out.println("✅ Message after decrypt: " + decryptedMessage);

                // ✅ Trích xuất domain từ câu rawMessage
                String domain = extractDomainFromText(decryptedMessage);
                if (domain == null) {
                    String response = "INVALID_MESSAGE_FORMAT";
                    exchange.sendResponseHeaders(400, response.length());
                    exchange.getResponseBody().write(response.getBytes());
                    return;
                }

                // ✅ Quét subdomain
                List<String> aliveSubs = SubdomainScanner.scanSubdomains(domain);

                StringBuilder responseBuilder = new StringBuilder();
                responseBuilder.append("✔ Scan success for domain: ").append(domain).append("\nAlive subdomains:\n");
                for (String sub : aliveSubs) {
                    responseBuilder.append(sub).append("\n");
                }

                String response = responseBuilder.toString();
                exchange.sendResponseHeaders(200, response.getBytes().length);
                exchange.getResponseBody().write(response.getBytes());

            } catch (Exception e) {
                e.printStackTrace();
                String error = "SERVER_ERROR";
                exchange.sendResponseHeaders(500, error.length());
                exchange.getResponseBody().write(error.getBytes());
            } finally {
                exchange.getResponseBody().close();
            }
        }

        private PrivateKey loadPrivateKey(String path) throws Exception {
            String pem = new String(Files.readAllBytes(Paths.get(path)));
            String base64Key = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                                  .replace("-----END PRIVATE KEY-----", "")
                                  .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(base64Key);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        }

        private String extractDomainFromText(String text) {
            // Trích domain từ dạng: "Scan subdomains for https://example.com"
            Pattern pattern = Pattern.compile("https?://([\\w.-]+)");
            Matcher matcher = pattern.matcher(text);
            if (matcher.find()) {
                return matcher.group(0); // hoặc group(1) nếu bạn chỉ muốn phần domain
            }
            return null;
        }
    }
}
