<?php
// Public route
if ($_SERVER['REQUEST_URI'] === '/public') {
    header('Content-Type: application/json');
    echo json_encode([
        "route" => "public",
        "message" => "This is a public route, accessible by anyone."
    ]);
    exit;
}

// Restricted route
if ($_SERVER['REQUEST_URI'] === '/restricted') {
    header('Content-Type: application/json');
    echo json_encode([
        "route" => "restricted",
        "message" => "You should only see this if middleware allows it."
    ]);
    exit;
}

// Fallback
http_response_code(404);
echo json_encode(["error" => "Not found"]);
