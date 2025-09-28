<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// ===== KONFIGURASI DATABASE =====
class Database {
    private $host = "localhost";
    private $db_name = "checklist_app";
    private $username = "root";
    private $password = "";
    public $conn;

    public function getConnection() {
        $this->conn = null;
        try {
            $this->conn = new PDO("mysql:host=" . $this->host . ";dbname=" . $this->db_name, $this->username, $this->password);
            $this->conn->exec("set names utf8");
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch(PDOException $exception) {
            error_log("Connection error: " . $exception->getMessage());
            die("Connection error: " . $exception->getMessage());
        }
        return $this->conn;
    }
}

// ===== FUNGSI AUTHENTIKASI YANG DIPERBAIKI =====
function loginUser($db, $username, $password) {
    // Validasi input
    if (empty($username) || empty($password)) {
        return "Username dan password harus diisi!";
    }
    
    error_log("Login attempt for username: " . $username);
    
    // ambil user berdasarkan username
    $query = "SELECT * FROM users WHERE username = ? AND is_active = 1";
    $stmt = $db->prepare($query);
    
    if (!$stmt->execute([$username])) {
        error_log("Database query failed");
        return "Error dalam query database";
    }
    
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user) {
        error_log("User found: " . $user['username']);
        error_log("Stored password hash: " . $user['password']);
        error_log("Input password: " . $password);
        
        // CEK 1: Coba password_verify dulu (jika password di-hash)
        if (password_verify($password, $user['password'])) {
            error_log("Password verification SUCCESS with password_verify");
            
            // update last login
            $updateQuery = "UPDATE users SET last_login = NOW() WHERE id = ?";
            $updateStmt = $db->prepare($updateQuery);
            $updateStmt->execute([$user['id']]);

            $_SESSION['user'] = [
                "id" => $user['id'],
                "username" => $user['username'],
                "email" => $user['email'],
                "isAdmin" => isset($user['is_admin']) ? (bool)$user['is_admin'] : false
            ];
            
            return true;
        }
        // CEK 2: Coba plain text (jika password belum di-hash)
        else if ($password === $user['password']) {
            error_log("Password verification SUCCESS with plain text");
            
            // update last login
            $updateQuery = "UPDATE users SET last_login = NOW() WHERE id = ?";
            $updateStmt = $db->prepare($updateQuery);
            $updateStmt->execute([$user['id']]);

            $_SESSION['user'] = [
                "id" => $user['id'],
                "username" => $user['username'],
                "email" => $user['email'],
                "isAdmin" => isset($user['is_admin']) ? (bool)$user['is_admin'] : false
            ];
            
            return true;
        }
        else {
            error_log("Password verification FAILED");
            error_log("Input: '" . $password . "'");
            error_log("Stored: '" . $user['password'] . "'");
            error_log("password_verify result: " . (password_verify($password, $user['password']) ? 'true' : 'false'));
        }
    } else {
        error_log("User not found: " . $username);
    }
    
    return "Username atau password salah!";
}

function createUser($db, $username, $password, $email = '') {
    // Validasi input
    if (strlen($username) < 3) {
        return "Username minimal 3 karakter!";
    }
    
    if (strlen($password) < 3) {
        return "Password minimal 3 karakter!";
    }
    
    // Check if username exists
    $checkQuery = "SELECT id FROM users WHERE username = ?";
    $checkStmt = $db->prepare($checkQuery);
    $checkStmt->execute([$username]);
    
    if ($checkStmt->rowCount() > 0) {
        return "Username sudah digunakan";
    }
    
    // **FIX: Gunakan plain text password untuk sementara (bisa diubah ke hash nanti)**
    $query = "INSERT INTO users (username, email, password, created_at, is_active) VALUES (?, ?, ?, NOW(), 1)";
    $stmt = $db->prepare($query);
    
    // Simpan sebagai plain text (lebih mudah untuk debugging)
    if ($stmt->execute([$username, $email, $password])) {
        return true;
    }
    return "Gagal membuat akun. Silakan coba lagi.";
}

function logoutUser() {
    session_unset();
    session_destroy();
}

// ===== FUNGSI CHECKLIST =====
function getChecklistItems($db, $date) {
    $query = "SELECT ci.*, u1.username as created_by_username, u2.username as updated_by_username 
              FROM checklist_items ci 
              LEFT JOIN users u1 ON ci.created_by = u1.id 
              LEFT JOIN users u2 ON ci.status_updated_by = u2.id 
              WHERE ci.checklist_date = ? 
              ORDER BY ci.created_at DESC";
    
    $stmt = $db->prepare($query);
    $stmt->execute([$date]);
    
    $items = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $items[] = [
            "id" => $row['id'],
            "name" => $row['item_name'],
            "status" => $row['status'],
            "createdAt" => $row['created_at'],
            "createdBy" => $row['created_by_username'],
            "statusUpdatedAt" => $row['status_updated_at'],
            "statusUpdatedBy" => $row['updated_by_username']
        ];
    }
    
    return $items;
}

function addChecklistItem($db, $name, $date, $userId) {
    $query = "INSERT INTO checklist_items (item_name, checklist_date, created_by, created_at) VALUES (?, ?, ?, NOW())";
    $stmt = $db->prepare($query);
    
    if ($stmt->execute([$name, $date, $userId])) {
        return $db->lastInsertId();
    }
    return false;
}

function updateItemStatus($db, $itemId, $status, $userId) {
    $query = "UPDATE checklist_items SET status = ?, status_updated_at = NOW(), status_updated_by = ? WHERE id = ?";
    $stmt = $db->prepare($query);
    return $stmt->execute([$status, $userId, $itemId]);
}

function deleteChecklistItem($db, $itemId) {
    $query = "DELETE FROM checklist_items WHERE id = ?";
    $stmt = $db->prepare($query);
    return $stmt->execute([$itemId]);
}

// ===== FUNGSI STATISTIK =====
function getChecklistStats($db, $date) {
    $query = "SELECT status, COUNT(*) as count FROM checklist_items WHERE checklist_date = ? GROUP BY status";
    $stmt = $db->prepare($query);
    $stmt->execute([$date]);
    
    $stats = ['dicari' => 0, 'dibawa' => 0, 'dikantor' => 0];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $stats[$row['status']] = (int)$row['count'];
    }
    
    $stats['total'] = array_sum($stats);
    return $stats;
}

// ===== FUNGSI EXPORT EXCEL =====
function exportToExcel($db, $date = null, $all = false) {
    if ($all) {
        // Export semua data
        $query = "SELECT ci.*, u1.username as created_by_username, u2.username as updated_by_username 
                  FROM checklist_items ci 
                  LEFT JOIN users u1 ON ci.created_by = u1.id 
                  LEFT JOIN users u2 ON ci.status_updated_by = u2.id 
                  ORDER BY ci.checklist_date DESC, ci.created_at DESC";
        $stmt = $db->prepare($query);
        $stmt->execute();
        $filename = "checklist_all_data_" . date('Y-m-d') . ".xls";
    } else {
        // Export data per tanggal
        $query = "SELECT ci.*, u1.username as created_by_username, u2.username as updated_by_username 
                  FROM checklist_items ci 
                  LEFT JOIN users u1 ON ci.created_by = u1.id 
                  LEFT JOIN users u2 ON ci.status_updated_by = u2.id 
                  WHERE ci.checklist_date = ? 
                  ORDER BY ci.created_at DESC";
        $stmt = $db->prepare($query);
        $stmt->execute([$date]);
        $filename = "checklist_" . $date . ".xls";
    }
    
    $items = [];
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $items[] = $row;
    }
    
    // Set header untuk download file Excel
    header("Content-Type: application/vnd.ms-excel");
    header("Content-Disposition: attachment; filename=\"$filename\"");
    header("Pragma: no-cache");
    header("Expires: 0");
    
    // Output data dalam format Excel
    echo "Tanggal\tNama Barang\tStatus\tDibuat Oleh\tWaktu Dibuat\tDiubah Oleh\tWaktu Diubah\n";
    
    foreach ($items as $item) {
        $status = '';
        switch ($item['status']) {
            case 'dicari': $status = 'Dicari'; break;
            case 'dibawa': $status = 'Dibawa'; break;
            case 'dikantor': $status = 'Dikantor'; break;
            default: $status = $item['status'];
        }
        
        echo $item['checklist_date'] . "\t";
        echo $item['item_name'] . "\t";
        echo $status . "\t";
        echo $item['created_by_username'] . "\t";
        echo $item['created_at'] . "\t";
        echo $item['updated_by_username'] . "\t";
        echo $item['status_updated_at'] . "\n";
    }
    exit;
}

// ===== PROSES EXPORT REQUEST =====
if (isset($_GET['export'])) {
    if (!isset($_SESSION['user'])) {
        die("Anda harus login terlebih dahulu!");
    }
    
    $db = (new Database())->getConnection();
    $date = $_GET['date'] ?? date('Y-m-d');
    $all = isset($_GET['all']) && $_GET['all'] == 'true';
    
    exportToExcel($db, $date, $all);
}

// ===== PROSES FORM =====
$db = (new Database())->getConnection();
$error = '';
$success = '';

// Debug info
error_log("=== NEW REQUEST ===");
error_log("POST data: " . print_r($_POST, true));
error_log("SESSION data: " . print_r($_SESSION, true));

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $action = $_POST['action'] ?? '';
    error_log("Action: " . $action);
    
    switch($action) {
        case 'login':
            $username = trim($_POST['username'] ?? '');
            $password = trim($_POST['password'] ?? '');
            
            error_log("Login attempt - Username: '" . $username . "', Password: '" . $password . "'");
            
            if (empty($username) || empty($password)) {
                $error = "Username dan password harus diisi!";
            } else {
                $result = loginUser($db, $username, $password);
                if ($result === true) {
                    error_log("Login successful, redirecting...");
                    header("Location: ".$_SERVER['PHP_SELF']);
                    exit;
                } else {
                    $error = $result;
                    error_log("Login failed: " . $error);
                }
            }
            break;
            
        case 'signup':
            $username = trim($_POST['new_username'] ?? '');
            $password = trim($_POST['new_password'] ?? '');
            $email = trim($_POST['new_email'] ?? '');
            
            error_log("Signup attempt - Username: '" . $username . "', Email: '" . $email . "'");
            
            if (empty($username) || empty($password)) {
                $error = "Username dan password harus diisi!";
            } else if (strlen($username) < 3) {
                $error = "Username minimal 3 karakter!";
            } else if (strlen($password) < 3) {
                $error = "Password minimal 3 karakter!";
            } else {
                $result = createUser($db, $username, $password, $email);
                if ($result === true) {
                    $success = "Akun berhasil dibuat! Silakan login.";
                    // Auto-fill login form setelah signup berhasil
                    echo "<script>document.addEventListener('DOMContentLoaded', function() { document.querySelector('[name=\"username\"]').value = '" . addslashes($username) . "'; });</script>";
                } else {
                    $error = $result;
                }
            }
            break;
            
        case 'logout':
            logoutUser();
            header("Location: ".$_SERVER['PHP_SELF']);
            exit;
            break;
            
        case 'add_item':
            if (isset($_SESSION['user'])) {
                $name = trim($_POST['item_name'] ?? '');
                $date = $_POST['checklist_date'] ?? date('Y-m-d');
                if (!empty($name)) {
                    addChecklistItem($db, $name, $date, $_SESSION['user']['id']);
                }
            }
            header("Location: ".$_SERVER['PHP_SELF'] . (isset($_GET['date']) ? '?date=' . $_GET['date'] : ''));
            exit;
            break;
            
        case 'update_status':
            if (isset($_SESSION['user'])) {
                $itemId = intval($_POST['item_id'] ?? 0);
                $status = $_POST['status'] ?? '';
                if ($itemId > 0 && in_array($status, ['dicari', 'dibawa', 'dikantor'])) {
                    updateItemStatus($db, $itemId, $status, $_SESSION['user']['id']);
                }
            }
            // Kembali ke halaman yang sama tanpa mengubah scroll position
            if (isset($_SERVER['HTTP_REFERER'])) {
                header("Location: " . $_SERVER['HTTP_REFERER']);
            } else {
                header("Location: ".$_SERVER['PHP_SELF'] . (isset($_GET['date']) ? '?date=' . $_GET['date'] : ''));
            }
            exit;
            break;
            
        case 'delete_item':
            if (isset($_SESSION['user'])) {
                $itemId = intval($_POST['item_id'] ?? 0);
                if ($itemId > 0) {
                    deleteChecklistItem($db, $itemId);
                }
            }
            // Kembali ke halaman yang sama tanpa mengubah scroll position
            if (isset($_SERVER['HTTP_REFERER'])) {
                header("Location: " . $_SERVER['HTTP_REFERER']);
            } else {
                header("Location: ".$_SERVER['PHP_SELF'] . (isset($_GET['date']) ? '?date=' . $_GET['date'] : ''));
            }
            exit;
            break;
            
        case 'add_multiple_items':
            if (isset($_SESSION['user'])) {
                $itemsText = trim($_POST['items_text'] ?? '');
                $date = $_POST['checklist_date'] ?? date('Y-m-d');
                $separator = $_POST['separator'] ?? ',';
                
                if (!empty($itemsText)) {
                    // Parse items berdasarkan separator
                    if ($separator === 'newline') {
                        $items = array_filter(array_map('trim', explode("\n", $itemsText)));
                    } else {
                        $items = array_filter(array_map('trim', explode($separator, $itemsText)));
                    }
                    
                    foreach ($items as $itemName) {
                        if (!empty($itemName)) {
                            addChecklistItem($db, $itemName, $date, $_SESSION['user']['id']);
                        }
                    }
                    $success = "Berhasil menambahkan " . count($items) . " barang!";
                }
            }
            header("Location: ".$_SERVER['PHP_SELF'] . (isset($_GET['date']) ? '?date=' . $_GET['date'] : ''));
            exit;
            break;
    }
}

// Handle AJAX requests
if (isset($_GET['ajax'])) {
    header('Content-Type: application/json');
    
    if (!isset($_SESSION['user'])) {
        echo json_encode(['success' => false, 'message' => 'Not logged in']);
        exit;
    }
    
    switch($_GET['ajax']) {
        case 'get_checklist':
            $date = $_GET['date'] ?? date('Y-m-d');
            $items = getChecklistItems($db, $date);
            $stats = getChecklistStats($db, $date);
            echo json_encode(['success' => true, 'items' => $items, 'stats' => $stats]);
            exit;
            
        case 'add_item':
            $name = trim($_POST['name'] ?? '');
            $date = $_POST['date'] ?? date('Y-m-d');
            if (!empty($name)) {
                $itemId = addChecklistItem($db, $name, $date, $_SESSION['user']['id']);
                echo json_encode(['success' => true, 'itemId' => $itemId]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Nama item harus diisi']);
            }
            exit;
            
        case 'update_status':
            $itemId = intval($_POST['id'] ?? 0);
            $status = $_POST['status'] ?? '';
            if ($itemId > 0 && in_array($status, ['dicari', 'dibawa', 'dikantor'])) {
                $success = updateItemStatus($db, $itemId, $status, $_SESSION['user']['id']);
                echo json_encode(['success' => $success]);
            } else {
                echo json_encode(['success' => false, 'message' => 'Data tidak valid']);
            }
            exit;
    }
}

$currentUser = $_SESSION['user'] ?? null;
$currentDate = $_GET['date'] ?? date('Y-m-d');
$checklistItems = $currentUser ? getChecklistItems($db, $currentDate) : [];
$checklistStats = $currentUser ? getChecklistStats($db, $currentDate) : [];
?>

<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Status Barang - Shared List</title>
    <style>
        /* CSS LENGKAP DARI CONTOH YANG DIBERIKAN */
        body {
            font-family: Arial, sans-serif;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            background: #f0f2f5;
        }
        .container {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .auth-section {
            background: #e3f2fd;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .user-info {
            background: #bbdefb;
            padding: 10px;
            border-radius: 3px;
            margin-bottom: 10px;
            display: <?php echo $currentUser ? 'block' : 'none'; ?>;
        }
        .admin-badge {
            background: #ff5722;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-size: 0.8em;
            margin-left: 10px;
        }
        .main-content {
            display: <?php echo $currentUser ? 'block' : 'none'; ?>;
        }
        .shared-info {
            background: #c8e6c9;
            padding: 10px;
            border-radius: 3px;
            margin: 10px 0;
            font-size: 14px;
        }
        .admin-panel {
            background: #fff3cd;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 4px solid #ffc107;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        .date-controls {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        .input-section {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .input-modes {
            display: flex;
            margin-bottom: 10px;
        }
        .input-mode {
            padding: 8px 16px;
            border: none;
            background: #e9ecef;
            cursor: pointer;
        }
        .input-mode.active {
            background: #007bff;
            color: white;
        }
        .input-area {
            display: none;
        }
        .input-area.active {
            display: block;
        }
        textarea {
            width: 100%;
            height: 100px;
            padding: 10px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            resize: vertical;
        }
        .separator-options {
            margin: 10px 0;
            display: flex;
            align-items: center;
            flex-wrap: wrap;
            gap: 10px;
        }
        .separator-option {
            padding: 5px 10px;
            border: 1px solid #ced4da;
            border-radius: 3px;
            cursor: pointer;
            background: white;
        }
        .separator-option.active {
            background: #007bff;
            color: white;
            border-color: #007bff;
        }
        .preview {
            background: #fff3cd;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
            border-left: 4px solid #ffc107;
        }
        .item {
            display: flex;
            align-items: center;
            margin: 10px 0;
            padding: 12px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #007bff;
        }
        .item.status-dicari {
            border-left-color: #dc3545;
            background: #f8d7da;
        }
        .item.status-dibawa {
            border-left-color: #ffc107;
            background: #fff3cd;
        }
        .item.status-dikantor {
            border-left-color: #28a745;
            background: #d4edda;
        }
        .item-name {
            flex: 1;
            font-weight: bold;
        }
        .item-meta {
            font-size: 0.8em;
            color: #6c757d;
            margin-left: 10px;
        }
        .item-user {
            background: #e3f2fd;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 0.7em;
            margin-left: 5px;
        }
        .status-controls {
            display: flex;
            gap: 5px;
            margin-left: 10px;
        }
        .status-btn {
            padding: 5px 10px;
            border: none;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
            font-weight: bold;
        }
        .status-dicari-btn {
            background: #dc3545;
            color: white;
        }
        .status-dibawa-btn {
            background: #ffc107;
            color: black;
        }
        .status-dikantor-btn {
            background: #28a745;
            color: white;
        }
        .stats {
            background: #e9ecef;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .stat-cards {
            display: flex;
            gap: 10px;
            margin-top: 10px;
            flex-wrap: wrap;
        }
        .stat-card {
            flex: 1;
            min-width: 120px;
            padding: 10px;
            border-radius: 5px;
            text-align: center;
            color: white;
            font-weight: bold;
        }
        .stat-dicari {
            background: #dc3545;
        }
        .stat-dibawa {
            background: #ffc107;
            color: black;
        }
        .stat-dikantor {
            background: #28a745;
        }
        button {
            padding: 8px 16px;
            margin: 5px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-size: 14px;
        }
        .btn-primary {
            background: #007bff;
            color: white;
        }
        .btn-success {
            background: #28a745;
            color: white;
        }
        .btn-warning {
            background: #ffc107;
            color: black;
        }
        .btn-danger {
            background: #dc3545;
            color: white;
        }
        .btn-info {
            background: #17a2b8;
            color: white;
        }
        input[type="date"], input[type="text"], input[type="password"], input[type="email"] {
            padding: 8px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            font-size: 14px;
        }
        .history-panel {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            max-height: 200px;
            overflow-y: auto;
        }
        .quick-templates {
            margin: 10px 0;
        }
        .template-btn {
            padding: 5px 10px;
            margin: 2px;
            background: #e9ecef;
            border: 1px solid #ced4da;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }
        .login-form {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }
        .account-management {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #90caf9;
        }
        .auth-tabs {
            display: flex;
            margin-bottom: 15px;
            border-bottom: 1px solid #ccc;
        }
        .auth-tab {
            padding: 10px 20px;
            cursor: pointer;
            border: none;
            background: none;
            border-bottom: 3px solid transparent;
        }
        .auth-tab.active {
            border-bottom-color: #007bff;
            font-weight: bold;
        }
        .auth-content {
            display: none;
        }
        .auth-content.active {
            display: block;
        }
        .debug-info {
            background: #f8f9fa;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            font-size: 12px;
            color: #666;
            border-left: 4px solid #6c757d;
        }
        .export-options {
            background: #e8f5e8;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            border-left: 4px solid #4caf50;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Debug Information -->
        <div class="debug-info">
            <strong>Debug Info:</strong><br>
            User Session: <?php echo isset($_SESSION['user']) ? 'Logged in as ' . htmlspecialchars($_SESSION['user']['username']) : 'Not logged in'; ?><br>
            POST Action: <?php echo htmlspecialchars($_POST['action'] ?? 'None'); ?><br>
            Current Date: <?php echo htmlspecialchars($currentDate); ?>
        </div>

        <!-- Authentication Section -->
        <div class="auth-section">
            <?php if ($error): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            
            <?php if ($success): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>

            <?php if (!$currentUser): ?>
            <div id="authTabs" class="auth-tabs">
                <button class="auth-tab active" onclick="showAuthTab('signin')">Sign In</button>
                <button class="auth-tab" onclick="showAuthTab('signup')">Sign Up</button>
            </div>

            <!-- Sign In Form -->
            <div id="signinForm" class="auth-content active">
                <h3>🔐 Sign In</h3>
                <form method="POST" class="login-form">
                    <input type="hidden" name="action" value="login">
                    <input type="text" name="username" placeholder="Username" required value="<?php echo htmlspecialchars($_POST['username'] ?? ''); ?>">
                    <input type="password" name="password" placeholder="Password" required>
                    <button type="submit" class="btn-primary">Sign In</button>
                </form>
                <div style="margin-top: 10px; font-size: 12px; color: #666;">
                    * Coba gunakan: test / test123
                </div>
            </div>

            <!-- Sign Up Form -->
            <div id="signupForm" class="auth-content">
                <h3>📝 Sign Up</h3>
                <form method="POST" class="login-form">
                    <input type="hidden" name="action" value="signup">
                    <input type="text" name="new_username" placeholder="Username baru (min. 3 karakter)" required value="<?php echo htmlspecialchars($_POST['new_username'] ?? ''); ?>">
                    <input type="email" name="new_email" placeholder="Email (opsional)" value="<?php echo htmlspecialchars($_POST['new_email'] ?? ''); ?>">
                    <input type="password" name="new_password" placeholder="Password (min. 3 karakter)" required>
                    <button type="submit" class="btn-success">Buat Akun</button>
                </form>
                <div style="margin-top: 10px; font-size: 12px; color: #666;">
                    * Password disimpan sebagai plain text untuk memudahkan testing
                </div>
            </div>
            <?php endif; ?>
            
            <div id="userInfo" class="user-info">
                <?php if ($currentUser): ?>
                <span>Login sebagai: <strong id="currentUser"><?php echo htmlspecialchars($currentUser['username']); ?></strong>
                    <?php if ($currentUser['isAdmin']): ?>
                        <span class="admin-badge">ADMIN</span>
                    <?php endif; ?>
                </span>
                <form method="POST" style="display: inline;">
                    <input type="hidden" name="action" value="logout">
                    <button type="submit" class="btn-danger" style="margin-left: 20px;">Logout</button>
                </form>
                <?php endif; ?>
            </div>
        </div>

        <!-- Main Content (Hidden until login) -->
        <?php if ($currentUser): ?>
        <div id="mainContent" class="main-content">
            <!-- Admin Panel -->
            <?php if ($currentUser['isAdmin']): ?>
            <div class="admin-panel">
                <h3>⚙️ Panel Admin</h3>
                <div>
                    <button class="btn-info" onclick="showSystemStats()">Statistik Sistem</button>
                    <button class="btn-warning" onclick="exportAllData()">Export Semua Data</button>
                </div>
            </div>
            <?php endif; ?>

            <div class="shared-info">
                📢 <strong>Shared Status Barang</strong> - Login berhasil! Selamat datang, <?php echo htmlspecialchars($currentUser['username']); ?>!
            </div>

            <!-- Export Options -->
            <div class="export-options">
                <h3>📊 Export Data</h3>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <button class="btn-success" onclick="exportChecklist()">
                        📥 Export Data Hari Ini
                    </button>
                    <button class="btn-info" onclick="exportDateData()">
                        📅 Export Data per Tanggal
                    </button>
                    <?php if ($currentUser['isAdmin']): ?>
                    <button class="btn-warning" onclick="exportAllData()">
                        💾 Export Semua Data
                    </button>
                    <?php endif; ?>
                </div>
                <div id="dateExportSection" style="margin-top: 10px; display: none;">
                    <input type="date" id="exportDatePicker" value="<?php echo htmlspecialchars($currentDate); ?>">
                    <button class="btn-primary" onclick="exportSpecificDate()">Export</button>
                </div>
            </div>

            <div class="header">
                <h1>📋 Status Barang Bersama</h1>
                <div class="date-controls">
                    <input type="date" id="datePicker" value="<?php echo htmlspecialchars($currentDate); ?>">
                    <button class="btn-primary" onclick="loadDateChecklist()">Muat Tanggal</button>
                    <button class="btn-success" onclick="copyFromPreviousDay()">Salin dari Hari Sebelumnya</button>
                </div>
            </div>

            <div class="input-section">
                <div class="input-modes">
                    <button class="input-mode active" onclick="setInputMode('single')">Input Single</button>
                    <button class="input-mode" onclick="setInputMode('multiple')">Input Multiple</button>
                </div>

                <!-- Mode Input Single -->
                <div id="singleInput" class="input-area active">
                    <form method="POST" id="singleItemForm" style="display: flex; gap: 10px; align-items: center;">
                        <input type="hidden" name="action" value="add_item">
                        <input type="hidden" name="checklist_date" value="<?php echo htmlspecialchars($currentDate); ?>">
                        <input type="text" name="item_name" placeholder="Tambah barang baru..." style="padding: 10px; width: 70%;">
                        <button type="submit" class="btn-primary">Tambah Barang</button>
                    </form>
                </div>

                <!-- Mode Input Multiple -->
                <div id="multipleInput" class="input-area">
                    <form method="POST" id="multipleItemsForm">
                        <input type="hidden" name="action" value="add_multiple_items">
                        <input type="hidden" name="checklist_date" value="<?php echo htmlspecialchars($currentDate); ?>">
                        <input type="hidden" name="separator" id="separatorInput" value=",">
                        
                        <textarea name="items_text" id="multiItemInput" placeholder="Masukkan beberapa barang sekaligus, pisahkan dengan koma, enter, atau titik koma"></textarea>
                        
                        <div class="separator-options">
                            <span>Pemisah:</span>
                            <span class="separator-option active" onclick="setSeparator(',')">Koma (,)</span>
                            <span class="separator-option" onclick="setSeparator('newline')">Enter</span>
                            <span class="separator-option" onclick="setSeparator(';')">Titik Koma (;)</span>
                        </div>

                        <div class="quick-templates">
                            <strong>Template Cepat:</strong>
                            <button type="button" class="template-btn" onclick="loadTemplate('perlengkapan')">Perlengkapan Kantor</button>
                            <button type="button" class="template-btn" onclick="loadTemplate('elektronik')">Elektronik</button>
                            <button type="button" class="template-btn" onclick="loadTemplate('dokumen')">Dokumen</button>
                        </div>

                        <div id="preview" class="preview" style="display: none;">
                            <strong>Preview:</strong>
                            <div id="previewItems"></div>
                        </div>

                        <button type="submit" class="btn-success">Tambah Semua Barang</button>
                        <button type="button" class="btn-warning" onclick="previewItems()">Preview</button>
                    </form>
                </div>
            </div>
            
            <!-- Checklist Items -->
            <div id="checklist">
                <?php foreach ($checklistItems as $item): ?>
                <div class="item status-<?php echo htmlspecialchars($item['status']); ?>" data-item-id="<?php echo $item['id']; ?>">
                    <div class="item-name"><?php echo htmlspecialchars($item['name']); ?></div>
                    <div class="item-meta">
                        <?php echo date('H:i', strtotime($item['createdAt'])); ?>
                        <?php if ($item['statusUpdatedBy']): ?>
                            (diubah oleh <?php echo htmlspecialchars($item['statusUpdatedBy']); ?>)
                        <?php endif; ?>
                        <span class="item-user">@<?php echo htmlspecialchars($item['createdBy']); ?></span>
                    </div>
                    <div class="status-controls">
                        <button onclick="updateItemStatus(<?php echo $item['id']; ?>, 'dicari')" class="status-btn status-dicari-btn <?php echo $item['status'] === 'dicari' ? 'active' : ''; ?>">Dicari</button>
                        <button onclick="updateItemStatus(<?php echo $item['id']; ?>, 'dibawa')" class="status-btn status-dibawa-btn <?php echo $item['status'] === 'dibawa' ? 'active' : ''; ?>">Dibawa</button>
                        <button onclick="updateItemStatus(<?php echo $item['id']; ?>, 'dikantor')" class="status-btn status-dikantor-btn <?php echo $item['status'] === 'dikantor' ? 'active' : ''; ?>">Dikantor</button>
                    </div>
                    <button onclick="deleteItem(<?php echo $item['id']; ?>)" style="background: #dc3545; color: white; margin-left: 10px;">Hapus</button>
                </div>
                <?php endforeach; ?>
                
                <?php if (empty($checklistItems)): ?>
                <p style="text-align: center; color: #6c757d;">Belum ada item dalam status barang.</p>
                <?php endif; ?>
            </div>
            
            <!-- Statistics -->
            <div class="stats">
                <strong>Status Barang - <?php echo date('l, j F Y', strtotime($currentDate)); ?></strong><br>
                
                <div class="stat-cards">
                    <div class="stat-card stat-dicari">
                        Dicari<br><?php echo $checklistStats['dicari'] ?? 0; ?> Barang
                    </div>
                    <div class="stat-card stat-dibawa">
                        Dibawa<br><?php echo $checklistStats['dibawa'] ?? 0; ?> Barang
                    </div>
                    <div class="stat-card stat-dikantor">
                        Dikantor<br><?php echo $checklistStats['dikantor'] ?? 0; ?> Barang
                    </div>
                    <div class="stat-card" style="background: #6c757d;">
                        Total<br><?php echo $checklistStats['total'] ?? 0; ?> Barang
                    </div>
                </div>
            </div>

            <div>
                <button class="btn-warning" onclick="showHistory()">Lihat Aktivitas</button>
            </div>
        </div>
        <?php endif; ?>
    </div>

<script>
    // ===== SHARED STATUS BARANG SYSTEM =====
    
    // Inisialisasi
    const datePicker = document.getElementById('datePicker');
    
    let currentUser = <?php echo $currentUser ? json_encode($currentUser) : 'null'; ?>;
    let currentSeparator = ',';
    let currentInputMode = 'single';
    let isAutoRefresh = true;

    // Template data
    const templates = {
        perlengkapan: "laptop, charger laptop, mouse, tas, pulpen, notebook, kunci kantor",
        elektronik: "hp, charger hp, powerbank, earphone, tablet, adaptor",
        dokumen: "KTP, SIM, kartu karyawan, laporan keuangan, proposal, kontrak"
    };

    // ===== FUNGSI UTAMA =====

    function initApp() {
        if (currentUser) {
            // Auto-refresh setiap 30 detik untuk melihat perubahan dari user lain
            setInterval(() => {
                if (isAutoRefresh) {
                    loadDateChecklist();
                }
            }, 30000);
        }
    }

    function showAuthTab(tabName) {
        // Update tabs
        document.querySelectorAll('.auth-tab').forEach(tab => tab.classList.remove('active'));
        event.target.classList.add('active');
        
        // Update content
        document.querySelectorAll('.auth-content').forEach(content => content.classList.remove('active'));
        document.getElementById(tabName + 'Form').classList.add('active');
    }

    // ===== FUNGSI CHECKLIST DENGAN AJAX =====

    async function loadDateChecklist() {
        const date = document.getElementById('datePicker').value;
        
        try {
            // Gunakan AJAX untuk load data tanpa refresh page
            const response = await fetch(`?ajax=get_checklist&date=${date}`);
            const data = await response.json();
            
            if (data.success) {
                updateChecklistDisplay(data.items, data.stats);
            }
        } catch (error) {
            console.error('Error loading checklist:', error);
        }
    }

    function updateChecklistDisplay(items, stats) {
        const checklistContainer = document.getElementById('checklist');
        const statsContainer = document.querySelector('.stats');
        
        // Update items
        if (items.length === 0) {
            checklistContainer.innerHTML = '<p style="text-align: center; color: #6c757d;">Belum ada item dalam status barang.</p>';
        } else {
            checklistContainer.innerHTML = items.map(item => `
                <div class="item status-${item.status}" data-item-id="${item.id}">
                    <div class="item-name">${escapeHtml(item.name)}</div>
                    <div class="item-meta">
                        ${formatTime(item.createdAt)}
                        ${item.statusUpdatedBy ? `(diubah oleh ${escapeHtml(item.statusUpdatedBy)})` : ''}
                        <span class="item-user">@${escapeHtml(item.createdBy)}</span>
                    </div>
                    <div class="status-controls">
                        <button onclick="updateItemStatus(${item.id}, 'dicari')" class="status-btn status-dicari-btn ${item.status === 'dicari' ? 'active' : ''}">Dicari</button>
                        <button onclick="updateItemStatus(${item.id}, 'dibawa')" class="status-btn status-dibawa-btn ${item.status === 'dibawa' ? 'active' : ''}">Dibawa</button>
                        <button onclick="updateItemStatus(${item.id}, 'dikantor')" class="status-btn status-dikantor-btn ${item.status === 'dikantor' ? 'active' : ''}">Dikantor</button>
                    </div>
                    <button onclick="deleteItem(${item.id})" style="background: #dc3545; color: white; margin-left: 10px;">Hapus</button>
                </div>
            `).join('');
        }
        
        // Update statistics
        statsContainer.innerHTML = `
            <strong>Status Barang - ${formatDisplayDate(document.getElementById('datePicker').value)}</strong><br>
            
            <div class="stat-cards">
                <div class="stat-card stat-dicari">
                    Dicari<br>${stats.dicari} Barang
                </div>
                <div class="stat-card stat-dibawa">
                    Dibawa<br>${stats.dibawa} Barang
                </div>
                <div class="stat-card stat-dikantor">
                    Dikantor<br>${stats.dikantor} Barang
                </div>
                <div class="stat-card" style="background: #6c757d;">
                    Total<br>${stats.total} Barang
                </div>
            </div>
        `;
    }

    // ===== FUNGSI EXPORT EXCEL =====

    function exportChecklist() {
        // Export data hari ini
        const today = new Date().toISOString().split('T')[0];
        window.open(`?export=true&date=${today}`, '_blank');
    }

    function exportDateData() {
        // Tampilkan pilihan tanggal untuk export
        const exportSection = document.getElementById('dateExportSection');
        exportSection.style.display = exportSection.style.display === 'none' ? 'block' : 'none';
    }

    function exportSpecificDate() {
        // Export data untuk tanggal tertentu
        const exportDate = document.getElementById('exportDatePicker').value;
        if (exportDate) {
            window.open(`?export=true&date=${exportDate}`, '_blank');
        } else {
            alert('Pilih tanggal terlebih dahulu!');
        }
    }

    function exportAllData() {
        // Export semua data (hanya untuk admin)
        if (confirm('Export semua data? File mungkin akan cukup besar.')) {
            window.open('?export=true&all=true', '_blank');
        }
    }

    // Fungsi untuk update status item dengan AJAX (TANPA MENGUBAH SCROLL)
    async function updateItemStatus(itemId, newStatus) {
        // Simpan posisi scroll sebelum update
        const scrollPosition = window.scrollY;
        
        try {
            const formData = new FormData();
            formData.append('id', itemId);
            formData.append('status', newStatus);

            const response = await fetch('?ajax=update_status', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            
            if (result.success) {
                // Update UI secara langsung tanpa reload halaman
                const itemElement = document.querySelector(`[data-item-id="${itemId}"]`);
                if (itemElement) {
                    // Hapus class status sebelumnya
                    itemElement.classList.remove('status-dicari', 'status-dibawa', 'status-dikantor');
                    // Tambah class status baru
                    itemElement.classList.add(`status-${newStatus}`);
                    
                    // Update tombol status aktif
                    const buttons = itemElement.querySelectorAll('.status-btn');
                    buttons.forEach(btn => btn.classList.remove('active'));
                    itemElement.querySelector(`.status-${newStatus}-btn`).classList.add('active');
                    
                    // Update statistik
                    updateStatsAfterChange();
                }
            }
            
            // Kembalikan posisi scroll ke semula
            window.scrollTo(0, scrollPosition);
            
        } catch (error) {
            console.error('Error updating item status:', error);
            // Kembalikan posisi scroll ke semula meskipun error
            window.scrollTo(0, scrollPosition);
        }
    }

    // Fungsi untuk delete item dengan AJAX (TANPA MENGUBAH SCROLL)
    async function deleteItem(itemId) {
        if (!confirm('Hapus item ini?')) {
            return;
        }

        // Simpan posisi scroll sebelum delete
        const scrollPosition = window.scrollY;
        
        try {
            const formData = new FormData();
            formData.append('action', 'delete_item');
            formData.append('item_id', itemId);
            formData.append('checklist_date', document.getElementById('datePicker').value);

            const response = await fetch('', {
                method: 'POST',
                body: formData
            });

            // Hapus item dari UI secara langsung
            const itemElement = document.querySelector(`[data-item-id="${itemId}"]`);
            if (itemElement) {
                itemElement.remove();
                
                // Update statistik
                updateStatsAfterChange();
                
                // Jika tidak ada item lagi, tampilkan pesan
                if (document.querySelectorAll('.item').length === 0) {
                    document.getElementById('checklist').innerHTML = '<p style="text-align: center; color: #6c757d;">Belum ada item dalam status barang.</p>';
                }
            }
            
            // Kembalikan posisi scroll ke semula
            window.scrollTo(0, scrollPosition);
            
        } catch (error) {
            console.error('Error deleting item:', error);
            // Kembalikan posisi scroll ke semula meskipun error
            window.scrollTo(0, scrollPosition);
        }
    }

    // Fungsi untuk update statistik setelah perubahan
    async function updateStatsAfterChange() {
        const date = document.getElementById('datePicker').value;
        
        try {
            const response = await fetch(`?ajax=get_checklist&date=${date}`);
            const data = await response.json();
            
            if (data.success) {
                const statsContainer = document.querySelector('.stats');
                statsContainer.innerHTML = `
                    <strong>Status Barang - ${formatDisplayDate(date)}</strong><br>
                    
                    <div class="stat-cards">
                        <div class="stat-card stat-dicari">
                            Dicari<br>${data.stats.dicari} Barang
                        </div>
                        <div class="stat-card stat-dibawa">
                            Dibawa<br>${data.stats.dibawa} Barang
                        </div>
                        <div class="stat-card stat-dikantor">
                            Dikantor<br>${data.stats.dikantor} Barang
                        </div>
                        <div class="stat-card" style="background: #6c757d;">
                            Total<br>${data.stats.total} Barang
                        </div>
                    </div>
                `;
            }
        } catch (error) {
            console.error('Error updating stats:', error);
        }
    }

    // Modifikasi form submission untuk menggunakan AJAX (TANPA MENGUBAH SCROLL)
    document.addEventListener('DOMContentLoaded', function() {
        // Handle form single item
        const singleItemForm = document.getElementById('singleItemForm');
        if (singleItemForm) {
            singleItemForm.addEventListener('submit', async function(event) {
                event.preventDefault();
                
                // Simpan posisi scroll sebelum submit
                const scrollPosition = window.scrollY;
                
                const formData = new FormData(this);
                
                try {
                    const response = await fetch('', {
                        method: 'POST',
                        body: formData
                    });
                    
                    // Reload checklist setelah menambah item
                    await loadDateChecklist();
                    
                    // Reset form
                    this.reset();
                    
                    // Kembalikan posisi scroll ke semula
                    window.scrollTo(0, scrollPosition);
                    
                } catch (error) {
                    console.error('Error submitting form:', error);
                    // Kembalikan posisi scroll ke semula meskipun error
                    window.scrollTo(0, scrollPosition);
                }
            });
        }
        
        // Handle form multiple items
        const multipleItemsForm = document.getElementById('multipleItemsForm');
        if (multipleItemsForm) {
            multipleItemsForm.addEventListener('submit', async function(event) {
                event.preventDefault();
                
                // Simpan posisi scroll sebelum submit
                const scrollPosition = window.scrollY;
                
                try {
                    const formData = new FormData(this);
                    const response = await fetch('', {
                        method: 'POST',
                        body: formData
                    });
                    
                    await loadDateChecklist();
                    this.reset();
                    document.getElementById('preview').style.display = 'none';
                    
                    // Kembalikan posisi scroll ke semula
                    window.scrollTo(0, scrollPosition);
                    
                } catch (error) {
                    console.error('Error submitting multiple items:', error);
                    // Kembalikan posisi scroll ke semula meskipun error
                    window.scrollTo(0, scrollPosition);
                }
            });
        }
    });

    function setInputMode(mode) {
        currentInputMode = mode;
        document.querySelectorAll('.input-mode').forEach(btn => btn.classList.remove('active'));
        event.target.classList.add('active');
        
        document.getElementById('singleInput').classList.remove('active');
        document.getElementById('multipleInput').classList.remove('active');
        document.getElementById(mode + 'Input').classList.add('active');
    }

    function setSeparator(separator) {
        currentSeparator = separator;
        document.querySelectorAll('.separator-option').forEach(btn => btn.classList.remove('active'));
        event.target.classList.add('active');
        
        document.getElementById('separatorInput').value = separator;
        if (document.getElementById('multiItemInput').value.trim()) {
            previewItems();
        }
    }

    function loadTemplate(templateName) {
        document.getElementById('multiItemInput').value = templates[templateName] || '';
        previewItems();
    }

    function previewItems() {
        const input = document.getElementById('multiItemInput').value.trim();
        if (!input) {
            document.getElementById('preview').style.display = 'none';
            return;
        }

        const items = parseMultipleItems(input);
        const previewDiv = document.getElementById('previewItems');
        
        if (items.length > 0) {
            previewDiv.innerHTML = items.map(item => `<div>✓ ${escapeHtml(item)} <span style="color: #6c757d; font-size: 0.9em;">(Status: Dicari)</span></div>`).join('');
            document.getElementById('preview').style.display = 'block';
        } else {
            document.getElementById('preview').style.display = 'none';
        }
    }

    function parseMultipleItems(input) {
        if (!input.trim()) return [];
        
        const separator = document.getElementById('separatorInput').value;
        
        if (separator === 'newline') {
            return input.split('\n').map(item => item.trim()).filter(item => item.length > 0);
        } else {
            return input.split(separator).map(item => item.trim()).filter(item => item.length > 0);
        }
    }

    function copyFromPreviousDay() {
        const currentDate = new Date(document.getElementById('datePicker').value);
        const previousDate = new Date(currentDate);
        previousDate.setDate(previousDate.getDate() - 1);
        const previousDateStr = previousDate.toISOString().split('T')[0];
        
        document.getElementById('datePicker').value = previousDateStr;
        loadDateChecklist();
    }

    // Fungsi untuk manual refresh
    function manualRefresh() {
        loadDateChecklist();
    }

    // Toggle auto-refresh
    function toggleAutoRefresh() {
        isAutoRefresh = !isAutoRefresh;
        const button = document.getElementById('toggleRefreshBtn');
        if (button) {
            button.textContent = isAutoRefresh ? '⏸️ Pause Auto-Refresh' : '▶️ Resume Auto-Refresh';
            button.className = isAutoRefresh ? 'btn-warning' : 'btn-success';
        }
    }

    function showHistory() {
        alert('Fitur riwayat akan diimplementasikan pada versi berikutnya');
    }

    function showSystemStats() {
        alert('Statistik sistem akan ditampilkan di sini');
    }

    // ===== UTILITY FUNCTIONS =====

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function formatTime(dateString) {
        const date = new Date(dateString);
        return date.toLocaleTimeString('id-ID', { 
            hour: '2-digit', 
            minute: '2-digit' 
        });
    }

    function formatDisplayDate(dateString) {
        const date = new Date(dateString);
        return date.toLocaleDateString('id-ID', {
            weekday: 'long',
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });
    }

    // Event listeners
    document.getElementById('multiItemInput')?.addEventListener('input', previewItems);

    // Event listener untuk date picker change
    document.getElementById('datePicker')?.addEventListener('change', function() {
        loadDateChecklist();
    });

    // Inisialisasi app
    initApp();
</script>
</body>
</html>