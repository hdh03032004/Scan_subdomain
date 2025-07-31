package com.doan.client;

import java.io.BufferedReader;
import java.io.FileReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class ClientSigner {
    public static PrivateKey loadPrivateKey(String pemFilePath) throws Exception {
        StringBuilder pem = new StringBuilder();
        try (BufferedReader br = new BufferedReader(new FileReader(pemFilePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (!line.contains("PRIVATE KEY"))
                    pem.append(line.trim());
            }
        }
        byte[] keyBytes = Base64.getDecoder().decode(pem.toString());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }

    public static String sign(String message, PrivateKey privateKey) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(privateKey);
        signer.update(message.getBytes(StandardCharsets.UTF_8));
        byte[] signatureBytes = signer.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }
}

