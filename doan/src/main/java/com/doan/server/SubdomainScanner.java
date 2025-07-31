package com.doan.server;

import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class SubdomainScanner {
    public static List<String> scanSubdomains(String domain) {
        String[] commonSubs = {
            "www", "mail", "ftp", "webmail", "ns1", "ns2", "portal", "vpn", "student", "admin"
        };

        List<String> alive = new ArrayList<>();

        for (String sub : commonSubs) {
            try {
                
                String fullUrl = domain.replace("https://", "https://" + sub + ".");
                HttpURLConnection conn = (HttpURLConnection) new URL(fullUrl).openConnection();
                conn.setConnectTimeout(3000);
                conn.setReadTimeout(3000);
                conn.setRequestMethod("HEAD");
                int code = conn.getResponseCode();

                if (code < 400) {
                    alive.add(fullUrl);
                }

                String ip = InetAddress.getByName(new URL(fullUrl).getHost()).getHostAddress();
                DatabaseUtils.insertScanResult(domain, fullUrl, "alive", ip);
            } catch (Exception ignored) {}
        }

        return alive;
    }
}

