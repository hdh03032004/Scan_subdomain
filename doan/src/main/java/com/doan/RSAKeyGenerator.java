package com.doan;

import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class RSAKeyGenerator {

    public static void main(String[] args) throws Exception {
        generateKeyPair("client");
        generateKeyPair("server");
    }

    private static void generateKeyPair(String name) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();

        // Private key
        String privateKeyPEM = "-----BEGIN PRIVATE KEY-----\n" +
                Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPrivate().getEncoded()) +
                "\n-----END PRIVATE KEY-----";
        try (OutputStreamWriter out = new OutputStreamWriter(
                new FileOutputStream("keys/" + name + "_private.pem"), StandardCharsets.UTF_8)) {
            out.write(privateKeyPEM);
        }

        // Public key
        String publicKeyPEM = "-----BEGIN PUBLIC KEY-----\n" +
                Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(pair.getPublic().getEncoded()) +
                "\n-----END PUBLIC KEY-----";
        try (OutputStreamWriter out = new OutputStreamWriter(
                new FileOutputStream("keys/" + name + "_public.pem"), StandardCharsets.UTF_8)) {
            out.write(publicKeyPEM);
        }

        System.out.println("✔ Tạo thành công cặp khóa RSA cho: " + name);
    }
}
