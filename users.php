<?php

echo "[+] Consulta de base de datos";

$server = "localhost";
$username = "<Your Username>";
$password = "***********";
$database = "targets";

$conn = new mysqli($server, $username, $password, $database);

if (!isset($_GET['id'])) {
    http_response_code(400); // Bad Request
}

//$id = mysqli_real_escape_string($conn, $_GET['id']); //Tested on secure input
$id = $_GET['id'];

$query = "SELECT username FROM users WHERE id = $id";
$result = $conn->query($query);

if ($result->num_rows === 0) {
    http_response_code(404); // Not Found
} else {
    $row = $result->fetch_assoc();
}

$conn->close();

?>
