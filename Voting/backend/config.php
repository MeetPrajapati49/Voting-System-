<?php
// Session configuration for CORS support - only set if session not already started
if (session_status() == PHP_SESSION_NONE) {
    ini_set('session.cookie_samesite', 'None');
    ini_set('session.cookie_secure', true); // Set to false if not using HTTPS
    ini_set('session.cookie_httponly', true);
    ini_set('session.use_only_cookies', 1);
    session_name('voting_session');
    session_start();
}

// MySQL database configuration
$host = 'localhost';
$dbname = 'voting';
$user = 'root';
$pass = '';

// DSN for MySQL
$dsn = "mysql:host=$host;dbname=$dbname;charset=utf8mb4";

try {
    $conn = new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
} catch (PDOException $e) {
    error_log("Database connection failed: " . $e->getMessage());
    die(json_encode(["success" => false, "message" => "Database connection failed: " . $e->getMessage()]));
}
?>
