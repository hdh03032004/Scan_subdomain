package com.doan.server;

import java.sql.*;

public class DatabaseUtils {
    private static final String URL = "jdbc:mysql://127.0.0.1:3306/secure_scan";
    private static final String USER = "root";     
    private static final String PASSWORD = "huy456789"; 

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (ClassNotFoundException e) {
            throw new RuntimeException("MySQL driver not found", e);
        }
    }

    public static void insertScanResult(String domain, String subdomain, String status, String ip) {
        String sql = "INSERT INTO scan_logs (domain, subdomain, status, ip) VALUES (?, ?, ?, ?)";
        try (Connection conn = DriverManager.getConnection(URL, USER, PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, domain);
            stmt.setString(2, subdomain);
            stmt.setString(3, status);
            stmt.setString(4, ip);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}