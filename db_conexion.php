<?php
// $servername = "localhost";
// $username = "root";
// $password = "";
// $database = "horarios";

$servername = "10.0.20.189";
$port = 3306;
$username = "root";
$password = "Jailton81*";
$database = "horarios";


// Crear una conexión a la base de datos
$conn = new mysqli($servername, $username, $password, $database, $port);

// Verificar la conexión
if ($conn->connect_error) {
    die("Error de conexión: " . $conn->connect_error);
}
?>