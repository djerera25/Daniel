<?php

$host = 'localhost';
$dbname = 'work';
$username = 'root';
$password = '';

try {
    $conn = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage());
}

session_start();

$action = isset($_GET['action']) ? $_GET['action'] : 'home';

if ($action === 'logout') {
    session_unset(); 
    session_destroy(); 
    header('Location: ?action=home');
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forum</title>
    <link rel="stylesheet" href="dan.css">
</head>
<body>
    <header>
        <h1>Forum</h1>
        <nav>
            <a href="?action=home">Home</a> | 
            <a href="?action=login">Login</a> | 
            <a href="?action=register">Register</a> | 
            <?php if (isset($_SESSION['username'])): ?>
                <a href="?action=logout">Logout</a>
            <?php endif; ?>
        </nav>
    </header>

    <div id="content">
        <?php
       
        if ($action === 'register') {
            echo <<<HTML
            <h2>Register</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Register</button>
            </form>
            HTML;

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $username = $_POST['username'];
                $password = password_hash($_POST['password'], PASSWORD_DEFAULT);

                $stmt = $conn->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
                $stmt->bindParam(':username', $username);
                $stmt->bindParam(':password', $password);

                if ($stmt->execute()) {
                    echo "<p>Registration successful! <a href='?action=login'>Login here</a></p>";
                } else {
                    echo "<p>Error: Unable to register.</p>";
                }
            }
        } 
        
        else if ($action === 'login') {
            echo <<<HTML
            <h2>Login</h2>
            <form method="POST">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            HTML;

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $username = $_POST['username'];
                $password = $_POST['password'];

                $stmt = $conn->prepare("SELECT * FROM users WHERE username = :username");
                $stmt->bindParam(':username', $username);
                $stmt->execute();
                $user = $stmt->fetch();

                if ($user && password_verify($password, $user['password'])) {
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    header('Location: ?action=home');
                    exit;
                } else {
                    echo "<p>Invalid credentials!</p>";
                }
            }
        }
        
        else if ($action === 'home') {
            echo "<h2>Forum Topics</h2>";

            $stmt = $conn->query("SELECT topics.*, users.username FROM topics JOIN users ON topics.created_by = users.id ORDER BY created_at DESC");
            $topics = $stmt->fetchAll();

            echo "<ul>";
            foreach ($topics as $topic) {
                echo "<li><a href='?action=view_topic&id=" . $topic['id'] . "'>" . htmlspecialchars($topic['title']) . "</a> by " . htmlspecialchars($topic['username']) . " on " . $topic['created_at'] . "</li>";
            }
            echo "</ul>";
           
            if (isset($_SESSION['username'])) {
                echo "<h3>Create New Topic</h3>
                      <form method='POST' action='?action=create_topic'>
                          <input type='text' name='title' placeholder='Topic Title' required>
   
                          <button type='submit'>Create Topic</button>
                      </form>";
            }
        } 
      
        else if ($action === 'create_topic') {
            if (!isset($_SESSION['user_id'])) {
                header('Location: ?action=login');
                exit;
            }

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $title = $_POST['title'];
         
                $userId = $_SESSION['user_id'];

                $stmt = $conn->prepare("INSERT INTO topics (title, created_by) VALUES (:title, :user_id)");
                $stmt->bindParam(':title', $title);
               
                $stmt->bindParam(':user_id', $userId);

                if ($stmt->execute()) {
                    echo "<p>Topic created successfully! <a href='?action=home'>Return to the forum</a></p>";
                } else {
                    echo "<p>Error: Unable to create topic.</p>";
                }
            }
        }
       
        else if ($action === 'view_topic') {
            $topicId = $_GET['id'];

            $stmt = $conn->prepare("SELECT * FROM topics WHERE id = :id");
            $stmt->bindParam(':id', $topicId);
            $stmt->execute();
            $topic = $stmt->fetch();

            if ($topic) {
                echo "<h2>" . htmlspecialchars($topic['title']) . "</h2>";
   

                $stmt = $conn->prepare("SELECT posts.*, users.username FROM posts JOIN users ON posts.created_by = users.id WHERE topic_id = :topic_id ORDER BY created_at ASC");
                $stmt->bindParam(':topic_id', $topicId);
                $stmt->execute();
                $posts = $stmt->fetchAll();

                echo "<ul>";
                foreach ($posts as $post) {
                    echo "<li><p>" . htmlspecialchars($post['content']) . "</p><small>by " . htmlspecialchars($post['username']) . " on " . $post['created_at'] . "</small></li>";
                }
                echo "</ul>";

                if (isset($_SESSION['user_id'])) {
                    echo "<a href='?action=post_message&topic_id=$topicId'>Post a Message</a>";
                }
            } else {
                echo "<p>Topic not found!</p>";
            }
        }

        else if ($action === 'post_message') {
            if (!isset($_SESSION['user_id'])) {
                header('Location: ?action=login');
                exit;
            }

            $topicId = $_GET['topic_id'];

            echo "<h2>Post a Message</h2>";
            echo "<form method='POST'>
                    <textarea name='content' placeholder='Write your message here' required></textarea>
                    <button type='submit'>Post Message</button>
                  </form>";

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                $content = $_POST['content'];
                $userId = $_SESSION['user_id'];

                $stmt = $conn->prepare("INSERT INTO posts (topic_id, content, created_by) VALUES (:topic_id, :content, :user_id)");
                $stmt->bindParam(':topic_id', $topicId);
                $stmt->bindParam(':content', $content);
                $stmt->bindParam(':user_id', $userId);

                if ($stmt->execute()) {
                    header("Location: ?action=view_topic&id=$topicId");
                    exit;
                } else {
                    echo "<p>Error: Unable to post message.</p>";
                }
            }
        }
        ?>
    </div>
</body>
</html>