package com.doan.server;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ServerVerifier {
    public static boolean verifySignature(String message, String base64Signature, String base64ClientPublicKey) throws Exception {
        byte[] keyBytes = parsePEMKey(base64ClientPublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        PublicKey clientPublicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(clientPublicKey);
        verifier.update(message.getBytes("UTF-8"));

        byte[] signatureBytes = Base64.getDecoder().decode(base64Signature);
        return verifier.verify(signatureBytes);
    }

    public static SecretKey decryptAESKey(String base64EncryptedAESKey, PrivateKey serverPrivateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, serverPrivateKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(base64EncryptedAESKey));
        return new SecretKeySpec(Base64.getDecoder().decode(new String(decrypted)), 0, 16, "AES");
    }

    private static byte[] parsePEMKey(String pem) {
        return Base64.getDecoder().decode(
            pem.replace("-----BEGIN PUBLIC KEY-----", "")
               .replace("-----END PUBLIC KEY-----", "")
               .replaceAll("\\s", "")
        );
    }
}
