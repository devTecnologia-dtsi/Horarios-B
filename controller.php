<?php
include "db_conexion.php";

function ejecutarConsulta($sql, $params = [])
{
    $data = [];
    global $servername, $port, $username, $password, $database;

    // Conexión a la base de datos
    $conn = new mysqli($servername, $username, $password, $database, $port);

    // Verificar la conexión
    if ($conn->connect_error) {
        die("Conexión fallida: " . $conn->connect_error);
    }

    // Protección contra la inyección SQL usando consultas preparadas
    $stmt = $conn->prepare($sql);

    if ($stmt === false) {
        die("Error en la preparación de la consulta: " . $conn->error);
    }

    // Vincular parámetros si es necesario
    if (!empty($params)) {
        $types = array_map(function ($param) {
            switch (gettype($param)) {
                case 'string':
                    return 's';
                case 'integer':
                    return 'i';
                default:
                    return 's';
            }
        }, $params);
        $stmt->bind_param(implode($types), ...$params);
    }

    // Ejecutar la consulta
    $stmt->execute();

    // Obtener los resultados si es una consulta SELECT
    if (stripos($sql, 'SELECT') !== false) {
        $result = $stmt->get_result();
        while ($row = $result->fetch_assoc()) {
            $data[] = $row;
        }
    } else {
        $data = true;
    }

    // Cerrar la conexión y la declaración
    $stmt->close();
    $conn->close();

    // Devolver los resultados
    return $data;
}
