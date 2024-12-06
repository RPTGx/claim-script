<?php
session_start();

// Add these constants at the top after session_start()
define('HCAPTCHA_SITE_KEY', 'bdf09fdc-b7b8-42b6-84d8-3fdeeb9ee82a');
define('HCAPTCHA_SECRET_KEY', 'ES_132d0dd0ee304eaca317f9e8a0e15c73');

// Completely revise validateAccess to handle the button click scenario
function validateAccess() {
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $hcaptchaResponse = $_POST['h-captcha-response'] ?? '';
        
        if (empty($hcaptchaResponse)) {
            return false;
        }

        $data = array(
            'secret' => HCAPTCHA_SECRET_KEY,
            'response' => $hcaptchaResponse
        );

        $verify = curl_init();
        curl_setopt($verify, CURLOPT_URL, "https://hcaptcha.com/siteverify");
        curl_setopt($verify, CURLOPT_POST, true);
        curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
        $response = curl_exec($verify);
        $responseData = json_decode($response);
        
        if (!$responseData->success) {
            return false;
        }

        // If CAPTCHA is valid, set a session flag and return true
        $_SESSION['captcha_verified'] = true;
        return true;
    } else {
        // Only show CAPTCHA if not already verified
        if (!isset($_SESSION['captcha_verified'])) {
            echo '<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verify Access</title>
                <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
                <link rel="stylesheet" href="alclaim.css">
            </head>
            <body>
                <div class="background"></div>
                <div class="message">
                    <h1>Verify You Are Human</h1>
                    <form method="POST" action="' . $_SERVER['PHP_SELF'] . '">
                        <div class="h-captcha" data-sitekey="' . HCAPTCHA_SITE_KEY . '"></div>
                        <button type="submit" class="button">Continue to Claim</button>
                    </form>
                </div>
            </body>
            </html>';
            exit();
        }
        
        return isset($_SESSION['captcha_verified']);
    }
}

// Modify the main flow to handle the CAPTCHA verification
if (!validateAccess()) {
    error_log("Access denied - IP: " . $_SERVER['REMOTE_ADDR']);
    http_response_code(403);
    die("Access denied");
}

// If we get here, CAPTCHA is verified, continue with URL assignment
// ... rest of your URL assignment code ...

// Add debug logging
error_log("Access granted - Session ID: " . session_id() . " First Access: " . (isset($_SESSION['first_access']) ? 'yes' : 'no'));

// Define secure path to private directory
define('PRIVATE_PATH', dirname($_SERVER['DOCUMENT_ROOT']) . '/private/reward-system');

// Function to create directories and ensure they exist
function ensureDirectoriesExist() {
    $directories = [
        PRIVATE_PATH,
        PRIVATE_PATH . '/urls',
        PRIVATE_PATH . '/data'
    ];

    foreach ($directories as $dir) {
        if (!file_exists($dir)) {
            if (!mkdir($dir, 0755, true)) {
                error_log("Failed to create directory: $dir");
                die("Configuration error");
            }
        }
    }
}

// Function to safely create and access files
function safeGetFile($filepath) {
    $directory = dirname($filepath);
    
    // Ensure directory exists
    if (!file_exists($directory)) {
        mkdir($directory, 0755, true);
    }
    
    // Create file if it doesn't exist
    if (!file_exists($filepath)) {
        file_put_contents($filepath, '');
        chmod($filepath, 0644);
    }
    
    return $filepath;
}

// Create necessary directories
ensureDirectoriesExist();

// Function to check if the user is using a mobile device
function isMobile() {
    $userAgent = strtolower($_SERVER['HTTP_USER_AGENT']);
    $mobileAgents = [
        'iphone', 'ipod', 'ipad', 'android', 'blackberry', 'webos', 'windows phone', 'opera mini', 'iemobile', 'mobile'
    ];

    foreach ($mobileAgents as $agent) {
        if (strpos($userAgent, $agent) !== false) {
            return true;
        }
    }
    return false;
}

// Function to load URLs from a file with debugging
function loadUrlsFromFile($filename) {
    try {
        if (!file_exists($filename)) {
            error_log("File does not exist: " . $filename);
            throw new Exception("File not found: $filename");
        }
        $urls = file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        error_log("URLs loaded from $filename: " . count($urls));
        return $urls ? array_map('trim', $urls) : [];
    } catch (Exception $e) {
        error_log($e->getMessage());
        return [];
    }
}

// Function to read CSV file
function readCsv($filename) {
    $rows = [];
    if (($handle = fopen($filename, 'r')) !== false) {
        while (($data = fgetcsv($handle)) !== false) {
            if (!empty($data[0]) && is_string($data[0])) {
                $rows[] = trim($data[0]);
            }
        }
        fclose($handle);
    }
    return array_unique($rows);
}

// Function to write to CSV file
function writeCsv($filename, $data) {
    if (($handle = fopen($filename, 'a')) !== false) {
        if (flock($handle, LOCK_EX)) {
            foreach ($data as $row) {
                $trimmedRow = trim($row);
                if (!empty($trimmedRow)) {
                    fputcsv($handle, [$trimmedRow]);
                }
            }
            flock($handle, LOCK_UN);
        } else {
            error_log("Could not lock file: $filename");
        }
        fclose($handle);
    } else {
        error_log("Could not open file: $filename");
    }
}

// Define and create necessary files
$desktopUrlsFile = safeGetFile(PRIVATE_PATH . '/urls/student_desktop_urls.txt');
$mobileUrlsFile = safeGetFile(PRIVATE_PATH . '/urls/student_mobile_urls.txt');
$devicesFile = safeGetFile(PRIVATE_PATH . '/data/devices_student.csv');
$visitedUrlsFile = safeGetFile(PRIVATE_PATH . '/data/visited_urls_student.csv');

// Add debugging logs
error_log("Desktop URLs file path: " . $desktopUrlsFile);
error_log("Mobile URLs file path: " . $mobileUrlsFile);

// Enhanced fingerprinting
function getClientFingerprint() {
    return hash('sha256', implode('|', [
        $_SERVER['HTTP_USER_AGENT'] ?? '',
        $_SERVER['REMOTE_ADDR'] ?? '',
        $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '',
        $_SERVER['HTTP_ACCEPT_ENCODING'] ?? '',
        $_SERVER['HTTP_ACCEPT'] ?? '',
        $_SERVER['HTTP_CONNECTION'] ?? '',
        $_SERVER['HTTP_HOST'] ?? '',
        $_SERVER['HTTP_SEC_CH_UA'] ?? '', // Browser brand detection
        $_SERVER['HTTP_SEC_CH_UA_PLATFORM'] ?? '', // Operating system detection
        $_SERVER['HTTP_SEC_CH_UA_MOBILE'] ?? '' // Mobile device detection
    ]));
}

// Device ID handling with enhanced security
$deviceId = $_COOKIE['visited'] ?? null;

if ($deviceId) {
    // Validate device ID format
    if (!preg_match('/^[a-f0-9]{32}$/', $deviceId)) {
        error_log("Invalid device ID format detected");
        http_response_code(403);
        die("Invalid session");
    }
    
    // Read all existing device-URL mappings
    $visitedDevices = file_exists($devicesFile) ? readCsv($devicesFile) : [];
    $visitedUrls = file_exists($visitedUrlsFile) ? readCsv($visitedUrlsFile) : [];
    
    // Find if this device already has a URL assigned
    $deviceIndex = array_search($deviceId, $visitedDevices);
    
    if ($deviceIndex !== false && isset($visitedUrls[$deviceIndex])) {
        // Device has a previous URL assigned
        $previousUrl = $visitedUrls[$deviceIndex];
        error_log("Returning user - Device ID: $deviceId, Assigned URL: $previousUrl");
        header("Location: " . $previousUrl);
        exit();
    }
}

// This section handles both new devices and devices without assigned URLs
$urlsFile = isMobile() ? $mobileUrlsFile : $desktopUrlsFile;
$availableUrls = loadUrlsFromFile($urlsFile);
$visitedUrls = file_exists($visitedUrlsFile) ? readCsv($visitedUrlsFile) : [];

// Remove already assigned URLs
$availableUrls = array_diff($availableUrls, $visitedUrls);

if (empty($availableUrls)) {
    error_log("No more unique URLs available");
    die("No more rewards available");
}

// Get the first available URL
$nextUrl = array_values($availableUrls)[0];

// If this is a new device, generate device ID and set cookie
if (!$deviceId) {
    $deviceId = bin2hex(random_bytes(16));
    setcookie('visited', $deviceId, [
        'expires' => time() + (10 * 365 * 24 * 60 * 60),
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
}

// Store the new device-URL mapping
writeCsv($devicesFile, [$deviceId]);
writeCsv($visitedUrlsFile, [$nextUrl]);

error_log("New user - Device ID: $deviceId, Assigned URL: $nextUrl");
header("Location: " . $nextUrl);
exit();
?>