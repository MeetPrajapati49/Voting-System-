<?php
// backend/aadhaar_auth.php - Aadhaar-based authentication
require_once "config.php";
require_once "aadhaar_config.php";
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

try {
    $input = json_decode(file_get_contents("php://input"), true);
    $action = $input["action"] ?? "";
$aadhaar_number = preg_replace('/\s+/', '', trim($input["aadhaar_number"] ?? ""));
    $mobile_number = preg_replace('/\s+/', '', trim($input["mobile_number"] ?? ""));
    $otp = trim($input["otp"] ?? "");

    if (!$action) {
        echo json_encode(["success" => false, "message" => "Action required"]);
        exit;
    }

    // Validate Aadhaar number format (12 digits)
    if ($aadhaar_number && !preg_match('/^\d{12}$/', $aadhaar_number)) {
        echo json_encode(["success" => false, "message" => "Invalid Aadhaar number format. Must be 12 digits."]);
        exit;
    }

    if ($action === "initiate") {
        // Initiate Aadhaar authentication
        if (!$aadhaar_number) {
            echo json_encode(["success" => false, "message" => "Aadhaar number required"]);
            exit;
        }

        $aadhaar_hmac = hmac_aadhaar($aadhaar_number);

        // Check if user already exists
        $stmt = $conn->prepare("SELECT id, username, role FROM users WHERE aadhaar_hmac = ?");
        $stmt->execute([$aadhaar_hmac]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user) {
            // User exists, generate OTP for login
            $otp_code = generate_otp();
            $_SESSION['aadhaar_auth'] = [
                'aadhaar_hmac' => $aadhaar_hmac,
                'mobile_number' => $mobile_number,
                'otp' => $otp_code,
                'expires' => time() + 300, // 5 minutes
                'user_id' => $user['id']
            ];

            // In production, send OTP via SMS/email
            // For demo, we'll return it in the response
            echo json_encode([
                "success" => true, 
                "message" => "OTP sent for verification",
                "otp" => $otp_code, // Remove this in production
                "user_exists" => true
            ]);
        } else {
            // New user, create temporary record and generate OTP
            $otp_code = generate_otp();
            $_SESSION['aadhaar_auth'] = [
                'aadhaar_hmac' => $aadhaar_hmac,
                'mobile_number' => $mobile_number,
                'otp' => $otp_code,
                'expires' => time() + 300, // 5 minutes
                'user_id' => null
            ];

            echo json_encode([
                "success" => true, 
                "message" => "OTP sent for new user registration",
                "otp" => $otp_code, // Remove this in production
                "user_exists" => false
            ]);
        }

    } elseif ($action === "verify") {
        // Verify OTP and complete authentication
        if (!$aadhaar_number || !$otp) {
            echo json_encode(["success" => false, "message" => "Aadhaar number and OTP required"]);
            exit;
        }

        $aadhaar_hmac = hmac_aadhaar($aadhaar_number);

        // Check session data
        if (!isset($_SESSION['aadhaar_auth']) || 
            $_SESSION['aadhaar_auth']['aadhaar_hmac'] !== $aadhaar_hmac ||
            $_SESSION['aadhaar_auth']['expires'] < time()) {
            echo json_encode(["success" => false, "message" => "Session expired or invalid"]);
            exit;
        }

        if ($_SESSION['aadhaar_auth']['otp'] != $otp) {
            echo json_encode(["success" => false, "message" => "Invalid OTP"]);
            exit;
        }

        $auth_data = $_SESSION['aadhaar_auth'];
        
        if ($auth_data['user_id']) {
            // Existing user - log them in
            $stmt = $conn->prepare("SELECT id, username, role FROM users WHERE id = ?");
            $stmt->execute([$auth_data['user_id']]);
            $user = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($user) {
                $_SESSION["user"] = [
                    "id" => $user["id"],
                    "username" => $user["username"],
                    "role" => $user["role"]
                ];
                
                unset($_SESSION['aadhaar_auth']);
                echo json_encode([
                    "success" => true, 
                    "message" => "Login successful",
                    "username" => $user["username"],
                    "id" => $user["id"],
                    "role" => $user["role"]
                ]);
            } else {
                echo json_encode(["success" => false, "message" => "User not found"]);
            }
        } else {
            // New user - create account
            $username = "aadhaar_" . substr($aadhaar_number, -4); // Simple username generation
$stmt = $conn->prepare("INSERT INTO users (username, aadhaar_hmac, role, created_at) VALUES (?, ?, 'user', NOW())");
$stmt->execute([$username, $aadhaar_hmac]);
            $userId = $conn->lastInsertId();

            $_SESSION["user"] = [
                "id" => $userId,
                "username" => $username,
                "role" => "user"
            ];
            
            unset($_SESSION['aadhaar_auth']);
            echo json_encode([
                "success" => true, 
                "message" => "Registration and login successful",
                "username" => $username,
                "id" => $userId,
                "role" => "user"
            ]);
        }

    } else {
        echo json_encode(["success" => false, "message" => "Invalid action"]);
    }

} catch (Exception $e) {
    // Detailed error logging for debugging
    error_log("Aadhaar auth error: " . $e->getMessage() . " in " . $e->getFile() . " on line " . $e->getLine());
    // Return detailed error message in development mode, generic in production
    $isDev = true; // Set to false in production
    if ($isDev) {
        echo json_encode(["success" => false, "message" => "Server error occurred: " . $e->getMessage()]);
    } else {
        echo json_encode(["success" => false, "message" => "Server error occurred"]);
    }
}
?>
