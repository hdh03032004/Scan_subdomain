CREATE DATABASE secure_scan;

USE secure_scan;

CREATE TABLE scan_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255),
    subdomain VARCHAR(255),
    status VARCHAR(20),
    ip VARCHAR(45),
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
