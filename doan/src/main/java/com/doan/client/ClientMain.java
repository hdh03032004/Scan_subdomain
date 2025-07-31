package com.doan.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class ClientMain {
    public static void main(String[] args) {
        try {
            // Nhập tên miền từ dòng lệnh hoặc stdin
            String domain;
            if (args.length > 0) {
                domain = args[0];
            } else {
                Scanner scanner = new Scanner(System.in);
                System.out.print("Enter domain (VD: huflit.edu.vn): ");
                domain = scanner.nextLine();
                scanner.close();
            }

            String rawMessage = "Scan subdomains for https://" + domain;
            String timestamp = String.valueOf(System.currentTimeMillis());

            // B1: Sinh AES key và IV
            SecretKey aesKey = AESUtils.generateAESKey(128);
            IvParameterSpec iv = AESUtils.generateIV();

            // B2: Mã hóa nội dung bằng AES
            String encryptedMessage = AESUtils.encrypt(rawMessage, aesKey, iv);

            // B3: Mã hóa khóa AES bằng RSA với khóa công khai của server
            PublicKey serverPublicKey = RSAUtils.loadPublicKeyFromPEM("keys/server_public.pem");
            String encryptedAESKey = RSAUtils.encryptWithRSA(
                    AESUtils.encodeKeyToBase64(aesKey), serverPublicKey
            );

            // B4: Ký nội dung gốc
            PrivateKey clientPrivateKey = ClientSigner.loadPrivateKey("keys/client_private.pem");
            String signature = ClientSigner.sign(rawMessage, clientPrivateKey);

            // B5: Tải public key client dưới dạng PEM
            String clientPublicKeyPEM = new String(
                    Files.readAllBytes(Paths.get("keys/client_public.pem")),
                    StandardCharsets.UTF_8
            );

            // B6: Tạo payload
            Payload payload = new Payload(
                    encryptedMessage,
                    encryptedAESKey,
                    AESUtils.encodeIVToBase64(iv),
                    rawMessage,
                    signature,
                    clientPublicKeyPEM
            );

            // B7: Gửi payload đến server
            URL url = new URL("http://localhost:8080/verify");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = payload.toJSONString().getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            System.out.println(">>> Payload have been sent server. Response message: " + conn.getResponseCode());

            // B8: Đọc phản hồi
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String line;
                System.out.println(">>> Response from server:");
                while ((line = in.readLine()) != null) {
                    System.out.println(line);
                }
            }

        } catch (Exception e) {
            System.err.println("Lỗi khi thực hiện gửi yêu cầu:");
            e.printStackTrace();
        }
    }
}
