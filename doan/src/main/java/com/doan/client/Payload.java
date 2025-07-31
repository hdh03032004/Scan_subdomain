package com.doan.client;

import org.json.JSONObject;

public class Payload {
    private final String encryptedMessage;
    private final String encryptedAESKey;
    private final String iv;
    private final String rawMessage;
    private final String signature;
    private final String clientPublicKey;

    public Payload(String encryptedMessage, String encryptedAESKey, String iv,
                   String rawMessage, String signature, String clientPublicKey) {
        this.encryptedMessage = encryptedMessage;
        this.encryptedAESKey = encryptedAESKey;
        this.iv = iv;
        this.rawMessage = rawMessage;
        this.signature = signature;
        this.clientPublicKey = clientPublicKey;
    }

    public String toJSONString() {
        JSONObject json = new JSONObject();
        json.put("encryptedMessage", encryptedMessage);
        json.put("encryptedAESKey", encryptedAESKey);
        json.put("iv", iv);
        json.put("rawMessage", rawMessage);
        json.put("signature", signature);
        json.put("clientPublicKey", clientPublicKey);
        return json.toString();
    }
    
}
