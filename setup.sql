CREATE DATABASE IF NOT EXISTS sqli_lab;
USE sqli_lab;
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50),
  email VARCHAR(100)
);
INSERT INTO users (username, email) VALUES
('alice','alice@example.com'),
('bob','bob@example.com'),
('carol','carol@example.com');
