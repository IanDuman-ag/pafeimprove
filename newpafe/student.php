<?php
// Suppress any output during PHP execution to prevent interference with JavaScript
ob_start();
session_start();
$_SESSION['user_name'] = isset($_SESSION['user_name']) ? $_SESSION['user_name'] : "John Doe";
// Temporary admin check (replace with your authentication logic)
$_SESSION['is_admin'] = isset($_SESSION['is_admin']) ? $_SESSION['is_admin'] : false; // Set to true for admin users

// Enable error reporting for debugging, but log to a file
ini_set('display_errors', 0);
ini_set('display_startup_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', 'logs/php_errors.log');
error_reporting(E_ALL);

// Database connection
$host = "localhost";
$username = "root";
$password = "";
$dbname = "dbpafe";

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    error_log("Connection failed: " . $e->getMessage());
    http_response_code(500);
    exit("Database connection failed. Please try again later.");
}

// Fetch user profile information
try {
    if (isset($_SESSION['user_id'])) {
        $stmt = $pdo->prepare("SELECT full_name FROM user_profile WHERE user_id = ?");
        $stmt->execute([$_SESSION['user_id']]);
        $user_profile = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user_profile) {
            $_SESSION['user_name'] = $user_profile['full_name'];
        }
    }
} catch (PDOException $e) {
    error_log("Error fetching user profile: " . $e->getMessage());
}

// Function to update event statuses
function updateEventStatuses($pdo) {
    try {
        $current_time = date('Y-m-d H:i:s');
        $stmt = $pdo->prepare("
            UPDATE events
            SET status = CASE
                WHEN status = 'Canceled' THEN 'Canceled'
                WHEN CONCAT(event_date, ' ', event_time) > ? THEN 'Scheduled'
                WHEN CONCAT(event_date, ' ', event_time) <= ? 
                    AND DATE_ADD(CONCAT(event_date, ' ', event_time), INTERVAL 2 HOUR) >= ? THEN 'Ongoing'
                ELSE 'Completed'
            END
            WHERE status != 'Canceled'
        ");
        $stmt->execute([$current_time, $current_time, $current_time]);
    } catch (PDOException $e) {
        error_log("Error updating event statuses: " . $e->getMessage());
    }
}

// Handle CRUD operations
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    $action = $_POST['action'];
    
    try {
        // Event CRUD
        if ($action === 'update_event') {
            $event_name = trim($_POST['event_name'] ?? '');
            $event_date = $_POST['event_date'] ?? '';
            $event_time = $_POST['event_time'] ?? '';
            $status = $_POST['status'] ?? '';
            $description = trim($_POST['description'] ?? '');

            if (empty($event_name) || empty($event_date) || empty($event_time) || empty($status)) {
                header("Location: ?page=events&error=All fields except description are required.");
                exit;
            }

            $id = $_POST['event_id'] ?? '';
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM events WHERE event_name = ? AND event_date = ? AND event_time = ? AND id != ?");
            $stmt->execute([$event_name, $event_date, $event_time, $id]);
            if ($stmt->fetchColumn() > 0) {
                header("Location: ?page=events&error=An event with the same name, date, and time already exists.");
                exit;
            } else {
                $stmt = $pdo->prepare("UPDATE events SET event_name = ?, event_date = ?, event_time = ?, status = ?, description = ? WHERE id = ?");
                $stmt->execute([$event_name, $event_date, $event_time, $status, $description, $id]);
                updateEventStatuses($pdo);
                header("Location: ?page=events&success=Event updated successfully.");
                exit;
            }
        }
        
        // Delete Event
        if ($action === 'delete_event') {
            $id = $_POST['event_id'] ?? '';
            $stmt = $pdo->prepare("DELETE FROM events WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: ?page=events&success=Event deleted successfully.");
            exit;
        }

        // Attendance Submission
        if ($action === 'submit_attendance') {
            $event_id = filter_var($_POST['event_id'] ?? '', FILTER_VALIDATE_INT);

            if (!$event_id) {
                header("Location: ?page=attendance&error=Invalid event ID.");
                exit;
            }

            try {
                // Get user profile information
                $stmt = $pdo->prepare("SELECT full_name, gender, year_level, section_name FROM user_profile WHERE user_id = ?");
                $stmt->execute([$_SESSION['user_id']]);
                $user_profile = $stmt->fetch(PDO::FETCH_ASSOC);

                if (!$user_profile) {
                    header("Location: ?page=attendance&error=User profile not found. Please update your profile first.");
                    exit;
                }

                // Check for duplicate attendance
                $stmt = $pdo->prepare("SELECT COUNT(*) FROM attendance WHERE fullname = ? AND event_id = ?");
                $stmt->execute([$user_profile['full_name'], $event_id]);
                if ($stmt->fetchColumn() > 0) {
                    header("Location: ?page=attendance&error=You have already submitted attendance for this event.");
                    exit;
                }

                // Insert new attendance record
                $stmt = $pdo->prepare("
                    INSERT INTO attendance (fullname, gender, year_level, section, status, event_id, created_at) 
                    VALUES (?, ?, ?, ?, 'Pending', ?, NOW())
                ");
                $stmt->execute([
                    $user_profile['full_name'],
                    $user_profile['gender'],
                    $user_profile['year_level'],
                    $user_profile['section_name'],
                    $event_id
                ]);
                
                header("Location: ?page=attendance&success=Attendance submitted successfully. Awaiting admin approval.");
                exit;
            } catch (PDOException $e) {
                error_log("Error submitting attendance: " . $e->getMessage());
                header("Location: ?page=attendance&error=An error occurred. Please try again.");
                exit;
            }
        }

        // Admin Approve Attendance
        if ($action === 'approve_attendance') {
            if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
                header("Location: ?page=attendance&error=Unauthorized action.");
                exit;
            }
            $id = filter_var($_POST['attendance_id'] ?? '', FILTER_VALIDATE_INT);
            if (!$id) {
                header("Location: ?page=attendance&error=Invalid attendance ID.");
                exit;
            }
            $stmt = $pdo->prepare("UPDATE attendance SET status = 'Approved' WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: ?page=attendance&success=Attendance approved successfully.");
            exit;
        }

        // Admin Reject Attendance
        if ($action === 'reject_attendance') {
            if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
                header("Location: ?page=attendance&error=Unauthorized action.");
                exit;
            }
            $id = filter_var($_POST['attendance_id'] ?? '', FILTER_VALIDATE_INT);
            if (!$id) {
                header("Location: ?page=attendance&error=Invalid attendance ID.");
                exit;
            }
            $stmt = $pdo->prepare("UPDATE attendance SET status = 'Rejected' WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: ?page=attendance&success=Attendance rejected successfully.");
            exit;
        }

        // Delete Attendance
        if ($action === 'delete_attendance') {
            if (!isset($_SESSION['is_admin']) || !$_SESSION['is_admin']) {
                header("Location: ?page=attendance&error=Unauthorized action.");
                exit;
            }
            $id = filter_var($_POST['attendance_id'] ?? '', FILTER_VALIDATE_INT);
            if (!$id) {
                header("Location: ?page=attendance&error=Invalid attendance ID.");
                exit;
            }
            $stmt = $pdo->prepare("DELETE FROM attendance WHERE id = ?");
            $stmt->execute([$id]);
            header("Location: ?page=attendance&success=Attendance record deleted successfully.");
            exit;
        }

        // Feedback Submission
        if ($action === 'submit_feedback') {
            $event_id = filter_var($_POST['event_id'] ?? '', FILTER_VALIDATE_INT);
            $comment = trim($_POST['comment'] ?? '');
            $rating = filter_var($_POST['rating'] ?? '', FILTER_VALIDATE_INT);

            // Validate inputs
            if (!$event_id || empty($comment) || !$rating) {
                header("Location: ?page=feedback&error=All feedback fields are required.");
                exit;
            }

            if ($rating < 1 || $rating > 5) {
                header("Location: ?page=feedback&error=Rating must be between 1 and 5.");
                exit;
            }

            // Check if user has already submitted feedback for this event
            $stmt = $pdo->prepare("SELECT COUNT(*) FROM feedback WHERE event_id = ? AND user_name = ?");
            $stmt->execute([$event_id, $_SESSION['user_name']]);
            if ($stmt->fetchColumn() > 0) {
                header("Location: ?page=feedback&error=You have already submitted feedback for this event.");
                exit;
            }

            // Check if status column exists in feedback table
            $stmt = $pdo->query("SHOW COLUMNS FROM feedback LIKE 'status'");
            $has_status_column = $stmt->rowCount() > 0;

            // Prepare and execute INSERT query
            if ($has_status_column) {
                $sql = "INSERT INTO feedback (event_id, user_name, comment, rating, status, created_at) VALUES (?, ?, ?, ?, 'Pending', NOW())";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$event_id, $_SESSION['user_name'], $comment, $rating]);
            } else {
                $sql = "INSERT INTO feedback (event_id, user_name, comment, rating, created_at) VALUES (?, ?, ?, ?, NOW())";
                $stmt = $pdo->prepare($sql);
                $stmt->execute([$event_id, $_SESSION['user_name'], $comment, $rating]);
            }

            header("Location: ?page=feedback&success=Feedback submitted successfully.");
            exit;
        }
    } catch (PDOException $e) {
        error_log("Error in CRUD operation ($action): " . $e->getMessage() . " | Query: " . (isset($sql) ? $sql : 'N/A'));
        header("Location: ?page=" . ($_GET['page'] ?? 'home') . "&error=An error occurred during operation. Please try again.");
        exit;
    }
}

// Fetch counts for Home section
try {
    $stmt = $pdo->query("SELECT COUNT(*) FROM events");
    $total_events = $stmt->fetchColumn();

    $stmt = $pdo->query("SELECT COUNT(*) FROM feedback");
    $total_feedback = $stmt->fetchColumn();

    $stmt = $pdo->query("SELECT COUNT(*) FROM attendance");
    $total_attendance = $stmt->fetchColumn();
} catch (PDOException $e) {
    $total_events = 0;
    $total_feedback = 0;
    $total_attendance = 0;
    error_log("Error fetching counts: " . $e->getMessage());
}

// Update event statuses
updateEventStatuses($pdo);

// Fetch all events
try {
    $stmt = $pdo->query("SELECT * FROM events ORDER BY event_date, event_time");
    $events = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $events = [];
    error_log("Error fetching events: " . $e->getMessage());
}

// Fetch attendance records with event names
try {
    if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']) {
        // Admins see all attendance records
        $stmt = $pdo->query("
            SELECT a.*, e.event_name, e.event_date, e.event_time 
            FROM attendance a 
            LEFT JOIN events e ON a.event_id = e.id 
            ORDER BY a.created_at DESC
        ");
    } else {
        // Regular users see their records (all statuses)
        $stmt = $pdo->prepare("
            SELECT a.*, e.event_name, e.event_date, e.event_time 
            FROM attendance a 
            LEFT JOIN events e ON a.event_id = e.id 
            WHERE a.fullname = ? 
            ORDER BY a.created_at DESC
        ");
        $stmt->execute([$_SESSION['user_name']]);
    }
    $attendances = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $attendances = [];
    error_log("Error fetching attendance: " . $e->getMessage());
}

// Fetch feedback records for the current user
try {
    $stmt = $pdo->prepare("
        SELECT f.*, e.event_name 
        FROM feedback f 
        LEFT JOIN events e ON f.event_id = e.id 
        WHERE f.user_name = ? 
        ORDER BY f.created_at DESC
    ");
    $stmt->execute([$_SESSION['user_name']]);
    $feedbacks = $stmt->fetchAll(PDO::FETCH_ASSOC);
} catch (PDOException $e) {
    $feedbacks = [];
    error_log("Error fetching feedback: " . $e->getMessage());
}

// Check for messages
$success = isset($_GET['success']) ? $_GET['success'] : null;
$error = isset($_GET['error']) ? $_GET['error'] : null;

// Clear output buffer to ensure no stray output
ob_end_clean();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Prime Association of Future Educators</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.0/main.min.css" rel="stylesheet">
    <style>
        body {
            font-family: 'Arial', sans-serif;
            background-color: #f4f4f4;
        }
        .sidebar {
            height: 100vh;
            position: fixed;
            top: 0;
            left: 0;
            width: 250px;
            background-color: #1a2b4e;
            padding-top: 20px;
            transition: all 0.3s;
            z-index: 1000;
        }
        .sidebar.collapsed {
            width: 80px;
        }
        .sidebar.collapsed .sidebar-text {
            display: none;
        }
        .sidebar.collapsed .nav-link {
            text-align: center;
        }
        .sidebar.collapsed .sidebar-logo, .sidebar.collapsed .sidebar-divider {
            display: none;
        }
        .sidebar .nav-link {
            color: #ffffff;
            padding: 10px 15px;
            margin: 5px 10px;
            border-radius: 5px;
            display: flex;
            align-items: center;
        }
        .sidebar .nav-link:hover {
            background-color: #2e4372;
        }
        .sidebar .nav-link i {
            margin-right: 10px;
            font-size: 1.2rem;
        }
        .sidebar-logo {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-bottom: 20px;
        }
        .sidebar-logo img {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            margin-bottom: 10px;
        }
        .sidebar-logo h4 {
            color: #ffffff;
            font-size: 1.2rem;
            text-align: center;
            margin: 0;
        }
        .sidebar-divider {
            border-top: 1px solid #ffffff;
            margin: 10px 20px;
            opacity: 0.3;
        }
        .sidebar-menu-header {
            color:rgb(255, 198, 12);
            font-size: 0.9rem;
            margin: 10px 20px 5px;
            text-transform: uppercase;
            opacity: 0.7;
        }
        .content {
            margin-left: 250px;
            padding: 20px;
            transition: all 0.3s;
            margin-top: 80px;
        }
        .content.expanded {
            margin-left: 80px;
        }
        .header {
            background-color:rgb(253, 191, 5);
            padding: 10px 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            position: fixed;
            width: calc(100% - 250px);
            top: 0;
            left: 250px;
            z-index: 999;
            transition: all 0.3s;
        }
        .header.expanded {
            width: calc(100% - 80px);
            left: 80px;
        }
        .user-img {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            object-fit: cover;
        }
        .toggle-btn {
            cursor: pointer;
            font-size: 20px;
        }
        .stat-card {
  background-color: #1a2b4e;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 15px;
            margin-bottom: 15px;
            text-align: center;
        }
        .stat-card i {
            font-size: 2rem;
            margin-bottom: 10px;
        }
        .stat-card h3 {
            margin: 10px 0;
            font-size: 1.5rem;
            color:rgb(255, 255, 255);
        }
        .stat-card p {
            margin: 0;
            font-size: 1.1rem;
            color:rgb(255, 255, 255);
        }
        .event-card, .feedback-card {
             background-color: #1a2b4e;
            color: #ffffff;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 15px;
            margin-bottom: 15px;
            transition: transform 0.2s;
            cursor: pointer;
        }
        .event-card:hover, .feedback-card:hover {
            transform: scale(1.02);
        }
        .status-scheduled { color: #007bff; }
        .status-ongoing { color: #28a745; }
        .status-completed { color: #6c757d; }
        .status-canceled { color: #dc3545; }
        .status-present { color: #28a745; }
        .status-absent { color: #dc3545; }
        .status-late { color: #ffc107; }
        .status-pending { color: #ffc107; }
        .status-approved { color: #28a745; }
        .status-rejected { color: #dc3545; }
        #calendar {
            max-width: 1100px;
            margin: 20px auto;
            background-color: #ffffff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .fc-event {
            cursor: pointer;
        }
        .fc-event-scheduled {
            background-color: #007bff;
            border-color: #007bff;
        }
        .fc-event-ongoing {
            background-color: #28a745;
            border-color: #28a745;
        }
        .fc-event-completed {
            background-color: #6c757d;
            border-color: #6c757d;
        }
        .fc-event-canceled {
            background-color: #dc3545;
            border-color: #dc3545;
        }
        .table {
            background-color: #ffffff;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .table th, .table td {
            vertical-align: middle;
        }
        @media (max-width: 768px) {
            .sidebar {
                width: 80px;
            }
            .sidebar .sidebar-text, .sidebar-logo, .sidebar-divider, .sidebar-menu-header {
                display: none;
            }
            .sidebar .nav-link {
                text-align: center;
            }
            .content {
                margin-left: 80px;
            }
            .header {
                width: calc(100% - 80px);
                left: 80px;
            }
            .table-responsive {
                font-size: 0.9rem;
            }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header" id="header">
        <div class="d-flex justify-content-between align-items-center">
            <div class="d-flex align-items-center">
                <h4 class="mb-0">Prime Association of Future Educators</h4>
            </div>
            <div class="d-flex align-items-center">
                <img src="pafenobg.png" alt="User" class="user-img me-2">
                <div class="dropdown">
                    <a class="dropdown-toggle text-dark text-decoration-none" href="#" role="button" id="userDropdown" data-bs-toggle="dropdown" aria-expanded="false">
                        <?php echo htmlspecialchars($_SESSION['user_name']); ?>
                    </a>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="userDropdown">
                        <li><a class="dropdown-item" href="#">Manage</a></li>
                        <li><a class="dropdown-item" href="logout.php">Log Out</a></li>
                        
                    </ul>
                </div>
            </div>
        </div>
    </header>

    <!-- Sidebar -->
    <nav class="sidebar" id="sidebar">
        <div class="sidebar-logo">
            <img src="PAFE.jpg" alt="Logo">
            <h4>P A F E</h4>
        </div>
        <div class="sidebar-divider"></div>
        <div class="d-flex justify-content-between align-items-center p-3">
            <h5 class="text-white sidebar-text mb-0">Menu</h5>
            <i class="fas fa-bars toggle-btn text-white" id="toggleBtn"></i>
        </div>
        <ul class="nav flex-column">
            <li class="nav-item">
                <a class="nav-link" href="?page=home"><i class="fas fa-home"></i><span class="sidebar-text">Home</span></a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="?page=events"><i class="fas fa-calendar-alt"></i><span class="sidebar-text">Events</span></a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="?page=attendance"><i class="fas fa-check-square"></i><span class="sidebar-text">Attendance</span></a>
            </li>
            <li class="nav-item">
                <a class="nav-link" href="?page=feedback"><i class="fas fa-comment-dots"></i><span class="sidebar-text">Feedback</span></a>
            </li>
        </ul>
    </nav>

    <!-- Main Content -->
    <div class="content" id="content">
        <?php
        $page = isset($_GET['page']) ? $_GET['page'] : 'home';
        ?>
        <?php if ($page === 'home'): ?>
            <h2>Welcome to the Prime Association of Future Educators</h2>
            <div class="row">
                <div class="col-md-4">
                    <div class="stat-card">
                        <i class="fas fa-calendar-alt text-primary"></i>
                        <h3><?php echo htmlspecialchars($total_events); ?></h3>
                        <p>Total Events</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="stat-card">
                        <i class="fas fa-comment-dots text-success"></i>
                        <h3><?php echo htmlspecialchars($total_feedback); ?></h3>
                        <p>Total Feedback</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="stat-card">
                        <i class="fas fa-check-square text-info"></i>
                        <h3><?php echo htmlspecialchars($total_attendance); ?></h3>
                        <p>Total Attendance</p>
                    </div>
                </div>
            </div>
            <h3 class="mt-4">Event Calendar</h3>
            <div id="calendar"></div>
            <!-- Event Details Modals -->
            <?php foreach ($events as $event): ?>
                <?php if (!isset($event['id'])) continue; ?>
                <div class="modal fade" id="detailsEventModal<?php echo htmlspecialchars($event['id']); ?>" tabindex="-1" aria-labelledby="detailsEventModalLabel<?php echo htmlspecialchars($event['id']); ?>" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="detailsEventModalLabel<?php echo htmlspecialchars($event['id']); ?>">Event Details</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <p><strong>Name:</strong> <?php echo htmlspecialchars($event['event_name'] ?? ''); ?></p>
                                <p><strong>Date:</strong> <?php echo htmlspecialchars($event['event_date'] ?? ''); ?></p>
                                <p><strong>Time:</strong> <?php echo htmlspecialchars($event['event_time'] ?? ''); ?></p>
                                <p><strong>Status:</strong> <span class="status-<?php echo strtolower($event['status'] ?? ''); ?>"><?php echo htmlspecialchars($event['status'] ?? ''); ?></span></p>
                                <p><strong>Description:</strong> <?php echo nl2br(htmlspecialchars($event['description'] ?? '')); ?></p>
                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($event['created_at'] ?? ''); ?></p>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php elseif ($page === 'events'): ?>
            <h2>Event Records</h2>
            <?php if (isset($success)): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <div class="table-responsive">
                <table class="table table-striped table-hover">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Date</th>
                            <th>Time</th>
                            <th>Status</th>
                            <th>Description</th>
                            <th>Created At</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($events)): ?>
                            <tr>
                                <td colspan="7" class="text-center">No events found.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($events as $event): ?>
                                <?php if (!isset($event['id'])) continue; ?>
                                <tr>
                                    <td><?php echo htmlspecialchars($event['event_name'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($event['event_date'] ?? ''); ?></td>
                                    <td><?php echo htmlspecialchars($event['event_time'] ?? ''); ?></td>
                                    <td><span class="status-<?php echo strtolower($event['status'] ?? ''); ?>"><?php echo htmlspecialchars($event['status'] ?? ''); ?></span></td>
                                    <td><?php echo nl2br(htmlspecialchars(substr($event['description'] ?? '', 0, 50) . (strlen($event['description'] ?? '') > 50 ? '...' : ''))); ?></td>
                                    <td><?php echo htmlspecialchars($event['created_at'] ?? ''); ?></td>
                                    <td>
                                        <button class="btn btn-info btn-sm" data-bs-toggle="modal" data-bs-target="#detailsEventModal<?php echo htmlspecialchars($event['id']); ?>">View</button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
            <!-- Event Details Modals -->
            <?php foreach ($events as $event): ?>
                <?php if (!isset($event['id'])) continue; ?>
                <div class="modal fade" id="detailsEventModal<?php echo htmlspecialchars($event['id']); ?>" tabindex="-1" aria-labelledby="detailsEventModalLabel<?php echo htmlspecialchars($event['id']); ?>" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="detailsEventModalLabel<?php echo htmlspecialchars($event['id']); ?>">Event Details</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <p><strong>Name:</strong> <?php echo htmlspecialchars($event['event_name'] ?? ''); ?></p>
                                <p><strong>Date:</strong> <?php echo htmlspecialchars($event['event_date'] ?? ''); ?></p>
                                <p><strong>Time:</strong> <?php echo htmlspecialchars($event['event_time'] ?? ''); ?></p>
                                <p><strong>Status:</strong> <span class="status-<?php echo strtolower($event['status'] ?? ''); ?>"><?php echo htmlspecialchars($event['status'] ?? ''); ?></span></p>
                                <p><strong>Description:</strong> <?php echo nl2br(htmlspecialchars($event['description'] ?? '')); ?></p>
                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($event['created_at'] ?? ''); ?></p>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php elseif ($page === 'attendance'): ?>
            <h2>Attendance Records</h2>
            <?php if (isset($success)): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <!-- Event Cards for Attendance Submission -->
            <h3>Submit Attendance</h3>
            <div class="row">
                <?php if (empty($events)): ?>
                    <p>No events available for attendance.</p>
                <?php else: ?>
                    <?php foreach ($events as $event): ?>
                        <?php if (!isset($event['id'])) continue; ?>
                        <div class="col-md-6 col-lg-4">
                            <div class="event-card" data-bs-toggle="modal" data-bs-target="#attendanceModal<?php echo htmlspecialchars($event['id']); ?>">
                                <h5><?php echo htmlspecialchars($event['event_name'] ?? ''); ?></h5>
                                <p><strong>Date:</strong> <?php echo htmlspecialchars($event['event_date'] ?? ''); ?></p>
                                <p><strong>Time:</strong> <?php echo htmlspecialchars($event['event_time'] ?? ''); ?></p>
                                <p><strong>Status:</strong> <span class="status-<?php echo strtolower($event['status'] ?? ''); ?>"><?php echo htmlspecialchars($event['status'] ?? ''); ?></span></p>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            <!-- Attendance Records Table -->
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">Attendance Records</h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Event</th>
                                    <th>Full Name</th>
                                    <th>Gender</th>
                                    <th>Year Level</th>
                                    <th>Section</th>
                                    <th>Status</th>
                                    <th>Created At</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($attendances)): ?>
                                    <tr>
                                        <td colspan="7" class="text-center">No attendance records found</td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($attendances as $attendance): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($attendance['event_name'] ?? ''); ?></td>
                                            <td><?php echo htmlspecialchars($attendance['fullname'] ?? ''); ?></td>
                                            <td><?php echo htmlspecialchars($attendance['gender'] ?? ''); ?></td>
                                            <td><?php echo htmlspecialchars($attendance['year_level'] ?? ''); ?></td>
                                            <td><?php echo htmlspecialchars($attendance['section'] ?? ''); ?></td>
                                            <td>
                                                <?php
                                                $statusClass = '';
                                                switch($attendance['status']) {
                                                    case 'Approved':
                                                        $statusClass = 'success';
                                                        break;
                                                    case 'Pending':
                                                        $statusClass = 'warning';
                                                        break;
                                                    case 'Rejected':
                                                        $statusClass = 'danger';
                                                        break;
                                                    default:
                                                        $statusClass = 'secondary';
                                                }
                                                ?>
                                                <span class="badge bg-<?php echo $statusClass; ?>">
                                                    <?php echo htmlspecialchars($attendance['status']); ?>
                                                </span>
                                            </td>
                                            <td><?php echo date('M d, Y h:i A', strtotime($attendance['created_at'])); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            <!-- Attendance Submission Modals -->
            <?php foreach ($events as $event): ?>
                <?php if (!isset($event['id'])) continue; ?>
                <div class="modal fade" id="attendanceModal<?php echo htmlspecialchars($event['id']); ?>" tabindex="-1" aria-labelledby="attendanceModalLabel<?php echo htmlspecialchars($event['id']); ?>" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="attendanceModalLabel<?php echo htmlspecialchars($event['id']); ?>">Submit Attendance</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <h6>Event Details</h6>
                                <p><strong>Name:</strong> <?php echo htmlspecialchars($event['event_name'] ?? ''); ?></p>
                                <p><strong>Date:</strong> <?php echo htmlspecialchars($event['event_date'] ?? ''); ?></p>
                                <p><strong>Time:</strong> <?php echo htmlspecialchars($event['event_time'] ?? ''); ?></p>
                                <hr>
                                <h6>Attendance Form</h6>
                                <form method="POST">
                                    <input type="hidden" name="action" value="submit_attendance">
                                    <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
                                    
                                    <?php
                                    // Get user profile information
                                    $stmt = $pdo->prepare("SELECT full_name, gender, year_level, section_name FROM user_profile WHERE user_id = ?");
                                    $stmt->execute([$_SESSION['user_id']]);
                                    $user_profile = $stmt->fetch(PDO::FETCH_ASSOC);
                                    
                                    if ($user_profile): ?>
                                        <div class="alert alert-info">
                                            <p><strong>Name:</strong> <?php echo htmlspecialchars($user_profile['full_name']); ?></p>
                                            <p><strong>Gender:</strong> <?php echo htmlspecialchars($user_profile['gender']); ?></p>
                                            <p><strong>Year Level:</strong> <?php echo htmlspecialchars($user_profile['year_level']); ?></p>
                                            <p><strong>Section:</strong> <?php echo htmlspecialchars($user_profile['section_name']); ?></p>
                                        </div>
                                        <button type="submit" class="btn btn-primary">Submit Attendance</button>
                                    <?php else: ?>
                                        <div class="alert alert-warning">
                                            Your profile information is not complete. Please update your profile first.
                                        </div>
                                    <?php endif; ?>
                                </form>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php elseif ($page === 'feedback'): ?>
            <h2>Feedback Records</h2>
            <?php if (isset($success)): ?>
                <div class="alert alert-success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>
            <?php if (isset($error)): ?>
                <div class="alert alert-danger"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <!-- Event Cards -->
            <h3>Available Events</h3>
            <div class="row">
                <?php if (empty($events)): ?>
                    <p>No events available for feedback.</p>
                <?php else: ?>
                    <?php foreach ($events as $event): ?>
                        <?php if (!isset($event['id'])) continue; ?>
                        <div class="col-md-6 col-lg-4">
                            <div class="event-card" data-bs-toggle="modal" data-bs-target="#feedbackEventModal<?php echo htmlspecialchars($event['id']); ?>">
                                <h5><?php echo htmlspecialchars($event['event_name'] ?? ''); ?></h5>
                                <p><strong>Date:</strong> <?php echo htmlspecialchars($event['event_date'] ?? ''); ?></p>
                                <p><strong>Time:</strong> <?php echo htmlspecialchars($event['event_time'] ?? ''); ?></p>
                                <p><strong>Status:</strong> <span class="status-<?php echo strtolower($event['status'] ?? ''); ?>"><?php echo htmlspecialchars($event['status'] ?? ''); ?></span></p>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
            <!-- Feedback Cards -->
            <h3>Your Feedback</h3>
            <div class="row">
                <?php if (!empty($feedbacks)): ?>
                    <?php foreach ($feedbacks as $feedback): ?>
                        <?php if (!isset($feedback['id'])) continue; ?>
                        <div class="col-md-6 col-lg-4" key="<?php echo htmlspecialchars($feedback['id']); ?>">
                            <div class="feedback-card">
                                <h5><?php echo htmlspecialchars($feedback['event_name'] ?? ''); ?></h5>
                                <p><strong>User:</strong> <?php echo htmlspecialchars($feedback['user_name'] ?? ''); ?></p>
                                <p><strong>Comment:</strong> <?php echo nl2br(htmlspecialchars($feedback['comment'] ?? '')); ?></p>
                                <p><strong>Rating:</strong> <?php echo htmlspecialchars($feedback['rating'] ?? ''); ?>/5</p>
                                <?php if (isset($feedback['status'])): ?>
                                    <p><strong>Status:</strong> <?php echo htmlspecialchars($feedback['status'] ?? ''); ?></p>
                                <?php endif; ?>
                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($feedback['created_at'] ?? ''); ?></p>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <p>You have not submitted any feedback yet.</p>
                <?php endif; ?>
            </div>
            <!-- Event Feedback Modals -->
            <?php foreach ($events as $event): ?>
                <?php if (!isset($event['id'])) continue; ?>
                <div class="modal fade" id="feedbackEventModal<?php echo htmlspecialchars($event['id']); ?>" tabindex="-1" aria-labelledby="feedbackEventModalLabel<?php echo htmlspecialchars($event['id']); ?>" aria-hidden="true">
                    <div class="modal-dialog">
                        <div class="modal-content">
                            <div class="modal-header">
                                <h5 class="modal-title" id="feedbackEventModalLabel<?php echo htmlspecialchars($event['id']); ?>">Event Feedback</h5>
                                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                            </div>
                            <div class="modal-body">
                                <h6>Event Details</h6>
                                <p><strong>Name:</strong> <?php echo htmlspecialchars($event['event_name'] ?? ''); ?></p>
                                <p><strong>Date:</strong> <?php echo htmlspecialchars($event['event_date'] ?? ''); ?></p>
                                <p><strong>Time:</strong> <?php echo htmlspecialchars($event['event_time'] ?? ''); ?></p>
                                <p><strong>Status:</strong> <span class="status-<?php echo strtolower($event['status'] ?? ''); ?>"><?php echo htmlspecialchars($event['status'] ?? ''); ?></span></p>
                                <p><strong>Description:</strong> <?php echo nl2br(htmlspecialchars($event['description'] ?? '')); ?></p>
                                <p><strong>Created At:</strong> <?php echo htmlspecialchars($event['created_at'] ?? ''); ?></p>
                                <hr>
                                <h6>Submit Feedback</h6>
                                <form method="POST">
                                    <input type="hidden" name="action" value="submit_feedback">
                                    <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
                                    <div class="mb-3">
                                        <label for="comment_<?php echo htmlspecialchars($event['id']); ?>" class="form-label">Comment</label>
                                        <textarea class="form-control" id="comment_<?php echo htmlspecialchars($event['id']); ?>" name="comment" rows="4" required></textarea>
                                    </div>
                                    <div class="mb-3">
                                        <label for="rating_<?php echo htmlspecialchars($event['id']); ?>" class="form-label">Rating (1-5)</label>
                                        <select class="form-select" id="rating_<?php echo htmlspecialchars($event['id']); ?>" name="rating" required>
                                            <option value="">Select Rating</option>
                                            <option value="1">1</option>
                                            <option value="2">2</option>
                                            <option value="3">3</option>
                                            <option value="4">4</option>
                                            <option value="5">5</option>
                                        </select>
                                    </div>
                                    <button type="submit" class="btn btn-primary">Submit Feedback</button>
                                </form>
                            </div>
                            <div class="modal-footer">
                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                            </div>
                        </div>
                    </div>
                </div>
            <?php endforeach; ?>
        <?php else: ?>
            <h2><?php echo ucfirst($page); ?></h2>
            <p>Content for <?php echo htmlspecialchars($page); ?> page goes here.</p>
        <?php endif; ?>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/fullcalendar@5.11.0/main.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const toggleBtn = document.getElementById('toggleBtn');
            const sidebar = document.getElementById('sidebar');
            const content = document.getElementById('content');
            const header = document.getElementById('header');

            toggleBtn.addEventListener('click', () => {
                sidebar.classList.toggle('collapsed');
                content.classList.toggle('expanded');
                header.classList.toggle('expanded');
            });

            const calendarEl = document.getElementById('calendar');
            if (calendarEl) {
                const calendar = new FullCalendar.Calendar(calendarEl, {
                    initialView: 'dayGridMonth',
                    events: [
                        <?php
                        $eventArray = [];
                        foreach ($events as $event) {
                            if (
                                !isset($event['id']) ||
                                !isset($event['event_name']) ||
                                !isset($event['event_date']) ||
                                !isset($event['event_time']) ||
                                !isset($event['status']) ||
                                !isset($event['description']) ||
                                !isset($event['created_at'])
                            ) {
                                error_log("Skipping event with missing fields: " . json_encode($event));
                                continue;
                            }
                            $eventData = [
                                'id' => $event['id'],
                                'title' => $event['event_name'],
                                'start' => $event['event_date'] . 'T' . $event['event_time'],
                                'end' => date('Y-m-d\TH:i:s', strtotime($event['event_date'] . ' ' . $event['event_time'] . ' +2 hours')),
                                'className' => 'fc-event-' . strtolower($event['status']),
                                'extendedProps' => [
                                    'description' => $event['description'],
                                    'status' => $event['status'],
                                    'time' => $event['event_time'],
                                    'created_at' => $event['created_at']
                                ]
                            ];
                            $eventArray[] = json_encode($eventData);
                        }
                        echo implode(',', $eventArray);
                        ?>
                    ],
                    eventClick: function(info) {
                        const modalId = `detailsEventModal${info.event.id}`;
                        const modal = document.getElementById(modalId);
                        if (modal) {
                            const bsModal = new bootstrap.Modal(modal);
                            bsModal.show();
                        }
                    },
                    height: 'auto',
                    headerToolbar: {
                        left: 'prev,next today',
                        center: 'title',
                        right: 'dayGridMonth,timeGridWeek,timeGridDay'
                    }
                });
                calendar.render();
            }
        });
    </script>
    <script>
    function checkAttendanceUpdates() {
        // Refresh the page every 30 seconds to check for updates
        setTimeout(function() {
            location.reload();
        }, 30000);
    }

    // Start checking for updates
    checkAttendanceUpdates();
    </script>
</body>
</html>