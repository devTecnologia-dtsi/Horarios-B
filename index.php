<?php

// Permitir solicitudes desde tu frontend
header("Access-Control-Allow-Origin: http://localhost:4200");
header("Access-Control-Allow-Headers: Authorization, Content-Type");
header("Access-Control-Allow-Methods: GET, POST, OPTIONS");

include "db_conexion.php";
include "controller.php";

require 'vendor/autoload.php';
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;


// Maneja solicitudes GET
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $data = [];
    $arrayArchivos = [];

    if (array_key_exists('horarios', $_GET)) {
        $stmt = $conn->prepare("SELECT * FROM horarios WHERE activo = 1;");

        $stmt->execute();

        $result = $stmt->get_result();

        while ($row = $result->fetch_assoc()) {
            $data[] = $row;
        }

        $stmt->close();
        $conn->close();

        echo json_encode($data);
    }

    if (array_key_exists('horario', $_GET)) {
        $stmt = $conn->prepare(
            "SELECT 
            h.nombre,
            c.id id_carpeta,
            c.ruta
            FROM horarios h
            INNER JOIN carpeta c ON c.horario_id = h.id
            WHERE h.id = ? AND c.carpeta_id IS NULL AND is_active IS TRUE;"
        );
        $id = $_GET['id'];
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $resultado = $stmt->get_result();

        $archivos = $conn->prepare(
            "SELECT 
            h.nombre,
            a.id id_archivo,
            a.ruta,
            a.nombre_archivo
            FROM horarios h
            INNER JOIN archivos a ON a.horario_id = h.id
            WHERE h.id = ?
            AND is_active IS TRUE;"
        );
        $archivos->bind_param("i", $id);
        $archivos->execute();
        $resultadoArchivos = $archivos->get_result();

        // iterate the folders
        while ($row = $resultado->fetch_assoc()) {
            $data[] = $row;
        }

        // iterate the fields
        while ($row = $resultadoArchivos->fetch_assoc()) {
            $arrayArchivos[] = $row;
        }

        $stmt->close();
        $conn->close();
        $resultadoArchivos->close();

        echo json_encode(array_merge($data, $arrayArchivos));
    }

    if (array_key_exists('carpeta', $_GET)) {

        if (!array_key_exists('id', $_GET) || empty($_GET['id'])) {
            echo json_encode(['message' => 'no hay id el cual consultar']);
            exit;
        }

        $stmt = $conn->prepare(
            "SELECT 
            c.ruta,
            c1.id id_carpeta,
            c1.ruta
            FROM carpeta c
            INNER JOIN carpeta c1 ON c1.carpeta_id = c.id 
            WHERE c.id = ?
            AND c.is_active IS TRUE
            AND c1.is_active IS TRUE;"
        );
        $id = $_GET['id'];
        $stmt->bind_param("i", $id);
        $stmt->execute();

        $resultado = $stmt->get_result();

        $archivos = $conn->prepare(
            "SELECT 
            a.id id_archivo,
            a.nombre_archivo
            FROM carpeta c
            INNER JOIN archivos a ON a.carpeta_id = c.id
            WHERE c.id = ?
            AND a.is_active IS TRUE;"
        );
        $archivos->bind_param("i", $id);
        $archivos->execute();
        $resultadoArchivos = $archivos->get_result();

        // iterate the folders
        while ($row = $resultado->fetch_assoc()) {
            $data[] = $row;
        }

        // iterate the fields
        while ($row = $resultadoArchivos->fetch_assoc()) {
            $arrayArchivos[] = $row;
        }

        $stmt->close();
        $conn->close();

        echo json_encode(array_merge($data, $arrayArchivos));
    }

    if (array_key_exists('ruta', $_GET)) {
        $result = [];
        $ruta = getPathByFolderId($_GET['id'], $conn);
        $rutas = explode("/", $ruta['ruta']);
        $rutaIds = explode("/", $ruta['rutas_ids']);

        $rutasWhitIds = array_map(function ($ruta, $index) use ($rutaIds) {
            if ($index != 0) {
                return ['nombre_ruta' => $ruta, 'id_ruta' => $rutaIds[$index - 1]];
            }
            return null;
        }, $rutas, array_keys($rutas));
        echo json_encode(array_values(array_filter($rutasWhitIds)));
    }

    if (array_key_exists('download', $_GET)) {
        $arrayFile = [];
        $stmt = $conn->prepare(
            "SELECT 
            ruta,
            nombre_archivo
            FROM archivos
            WHERE id = ?
            AND is_active IS TRUE;"
        );
        $id = $_GET['id'];
        $stmt->bind_param("i", $id);
        $stmt->execute();
        $resultado = $stmt->get_result();
        $arrayResult = $resultado->fetch_assoc();

        if ($arrayResult) {
            // Ruta del archivo en el servidor
            $archivo = $arrayResult['ruta'];
            $nombreArchivo = $arrayResult['nombre_archivo'];
            $contentSize = filesize($archivo);

            if (file_exists($archivo)) {
                // Configura las cabeceras de respuesta para la descarga
                header("Cache-Control: public");
                header("Content-Description: File Transfer");
                header("Content-Disposition: attachment; filename=$nombreArchivo");
                header("Content-Type: application/zip");
                header("Content-Transfer-Encoding: binary");
                header("Content-Length: $contentSize");

                // Lee el archivo y envíalo al cliente
                readfile($archivo);
                exit;
            }
        }

        http_response_code(404);
        echo json_encode(['message' => 'El archivo no se encuentra en el servidor.']);
    }

//     if (array_key_exists('permissions', $_GET)) {
//         try {
//             if (!array_key_exists('email', $_GET)) {
//                 throw new Exception("El email es un campo obligatorio");
//             }
//             $email = $_GET['email'];
//             if (empty($email)) {
//                 throw new Exception("El campo email no puede ser vacio");
//             }


//             $sql = "SELECT * FROM usuario WHERE correo = ? AND is_active IS TRUE";
//             $resultado = ejecutarConsulta($sql, [trim(mb_strtolower($email))]);
//             if (empty($resultado)) {
//                 throw new Exception("No tiene permisos para ingresar");
//             }

//             echo json_encode([
//                 'message' => 'acceso concedido',
//                 'process' => true
//             ]);
//             exit;
//         } catch (\Exception $e) {
//             echo json_encode([
//                 'message' => $e->getMessage(),
//                 'process' => false
//             ]);
//             exit;
//         }
//     }


}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    if (isset($_GET['permissions'])) {
        try {
            header('Content-Type: application/json');

            // Leer el token del header
            $authHeader = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
            if (!$authHeader || stripos($authHeader, 'Bearer ') !== 0) {
                throw new Exception("Token no proporcionado");
            }
            $jwt = substr($authHeader, 7);

            // Cargar las claves públicas de Azure AD (JWKS)
            $tenantId = "b1ba85eb-a253-4467-9ee8-d4f8ed4df300";
            $jwksUrl = "https://login.microsoftonline.com/{$tenantId}/discovery/v2.0/keys";

            $cacheFile = __DIR__ . "/jwks_cache.json";
            if (!file_exists($cacheFile) || (time() - filemtime($cacheFile)) > 3600) {
                $jwksJson = file_get_contents($jwksUrl);
                file_put_contents($cacheFile, $jwksJson);
            } else {
                $jwksJson = file_get_contents($cacheFile);
            }

            $jwks = json_decode($jwksJson, true);
            if (!$jwks || !isset($jwks['keys'])) {
                throw new Exception("No se pudieron obtener las claves públicas de Azure");
            }

            foreach ($jwks['keys'] as &$key) {
                if (!isset($key['alg'])) {
                    $key['alg'] = 'RS256';
                }
            }
            unset($key);

            // Validar token (id_token)
            $keys = JWK::parseKeySet($jwks);
            $decoded = JWT::decode($jwt, $keys);

            // Validar audiencia, debe ser el Client ID del frontend
            $expectedAud = "8fa1cb24-e6f1-42e6-a7be-2eefcd22df42";
            if ($decoded->aud !== $expectedAud) {
                throw new Exception("Audiencia inválida: " . $decoded->aud);
            }

            // Validar expiración
            if (isset($decoded->exp) && $decoded->exp < time()) {
                throw new Exception("El token ha expirado");
            }

            // Extraer email
            $email = $decoded->preferred_username ?? $decoded->upn ?? $decoded->email ?? null;
            if (!$email) {
                throw new Exception("No se pudo extraer el correo del token");
            }

            // Validar usuario en la BD
            $sql = "SELECT * FROM usuario WHERE correo = ? AND is_active IS TRUE";
            $resultado = ejecutarConsulta($sql, [trim(mb_strtolower($email))]);
            if (empty($resultado)) {
                throw new Exception("No tiene permisos para ingresar");
            }

            echo json_encode([
                'message' => 'Acceso concedido',
                'process' => true,
                'user' => [
                    'email' => $email,
                    'name'  => $decoded->name ?? ''
                ]
            ]);
            exit;

        } catch (\Exception $e) {
            http_response_code(401);
            echo json_encode([
                'message' => $e->getMessage(),
                'process' => false
            ]);
            exit;
        }
    }

    if (isset($_FILES['file'])) {
        $file = $_FILES['file'];
        $id = $_POST['id'];
        $isFolder = $_POST['isFolder'];

        if ($file['error'] === UPLOAD_ERR_OK) {

            // build the path
            if (filter_var($isFolder, FILTER_VALIDATE_BOOLEAN)) {
                $targetDirectory = getPathByFolderId($id, $conn);
            } else {
                $targetDirectory = getPathHorario($id, false, $conn);
            }

            $fileName = validateDocumentName(basename($file['name']));
            $targetFile = '../horarios/' . $targetDirectory['ruta'] . '/' . $fileName;

            if (move_uploaded_file($file['tmp_name'], $targetFile)) {

                // validate if the file exist on BD
                $validate = validateFile($id, $fileName, $targetFile, $isFolder, $conn);
                if (empty($validate)) {

                    // save the file on the bd
                    $file = saveFile($id, $fileName, $targetFile, $isFolder, $conn);
                    if (!$file) {
                        echo json_encode([
                            'message' => 'Hubo un error al guardar el archivo',
                            'process' => false
                        ]);
                        exit;
                    }
                }
                // El archivo se ha guardado correctamente.
                echo json_encode([
                    'message' => 'Archivo subido con éxito',
                    'process' => true
                ]);
            } else {
                // Error al mover el archivo.
                echo json_encode([
                    'message' => 'Error al mover el archivo',
                    'process' => false
                ]);
            }
        } else {
            // Error en la carga del archivo.
            echo json_encode([
                'message' => 'Error en la carga del archivo',
                'process' => false
            ]);
        }
    }

    if (array_key_exists('type', $_POST)) {

        if ($_POST['type'] == 'deleteFile') {
            $id = $_POST['id'];
            if (empty($id)) {
                echo json_encode([
                    'message' => 'No se envio el id del archivo que se quiere eliminar',
                    'process' => false
                ]);
                exit;
            }
            $sql = "SELECT
                ruta
                FROM archivos
                WHERE id = ?";
            $archivo = $conn->prepare($sql);
            $archivo->bind_param("i", $id);
            $archivo->execute();
            $resultadoArchivo = $archivo->get_result();
            $resultado = $resultadoArchivo->fetch_assoc();

            // se valide que exista en la base de datos
            if (empty($resultado)) {
                echo json_encode(['message' => 'El archivo no existe', 'process' => false]);
                exit;
            }

            // se valida que el archivo exista dentro del servidor
            if (!file_exists($resultado['ruta'])) {
                echo json_encode(['message' => 'El archivo ya no existe dentro del servidor', 'process' => false]);
                exit;
            }

            // se valida que se haya podido eliminar dentro del servidor
            if (!unlink($resultado['ruta'])) {
                echo json_encode(['message' => 'Hubo un error al eliminar el archivo en el servidor', 'process' => false]);
                exit;
            }

            $query = $conn->prepare(
                "UPDATE archivos SET is_active = 0 WHERE id = ?"
            );
            $query->bind_param("i", $id);
            if (empty($query->execute())) {
                echo json_encode([
                    'message' => 'Hubo un error al actualizar el archivo',
                    'process' => false
                ]);
                exit;
            }
            echo json_encode([
                'message' => 'Se elimino con exito el archivo',
                'process' => true
            ]);
            exit;
        }

        if ($_POST['type'] == 'deleteFolder') {
            // se valida que venga el dato que se quiere eliminar
            if (!array_key_exists('id', $_POST)) {
                echo json_encode([
                    'message' => 'El id es un campo requerido',
                    'process' => false
                ]);
                exit;
            }
            $id = $_POST['id'];

            // se valida que la carpeta no tenga archivos o mas carpetas dentro
            $sql = "SELECT
                        CASE WHEN c.id = a.carpeta_id THEN NULL ELSE c.ruta END carpeta,
                        COALESCE(a.nombre_archivo, NULL) AS archivo
                    FROM carpeta c
                    LEFT JOIN carpeta c1 ON c1.carpeta_id = c.id AND c1.is_active IS TRUE
                    LEFT JOIN archivos a ON a.carpeta_id = c.id AND a.is_active IS TRUE
                    WHERE (c.carpeta_id = ? OR a.carpeta_id = ?)
                    AND c.is_active IS TRUE;";
            $resultado = ejecutarConsulta($sql, [$id, $id]);
            if (!empty($resultado)) {
                echo json_encode([
                    'message' => 'No se puede eliminar la carpeta porque tiene informacion dentro',
                    'process' => false
                ]);
                exit;
            }

            $resultado = getPathByFolderId($id, $conn);

            $ruta = '../horarios/' . $resultado['ruta'];
            // se valida que la carpeta exista dentro del servidor
            if (!file_exists($ruta)) {
                echo json_encode(['message' => 'La carpeta ya no existe dentro del servidor', 'process' => false]);
                exit;
            }

            // se valida que se haya podido eliminar la carpeta dentro del servidor
            if (!rmdir($ruta)) {
                echo json_encode(['message' => 'Hubo un error al eliminar el archivo en el servidor', 'process' => false]);
                exit;
            }

            $sql = 'UPDATE carpeta SET is_active = FALSE WHERE id = ?';
            $resultado = ejecutarConsulta($sql, [$id]);
            if ($resultado) {
                echo json_encode([
                    'message' => 'Se elimino la carpeta con exito',
                    'process' => true
                ]);
            } else {
                echo json_encode([
                    'message' => 'Hubo un error al eliminar la carpeta',
                    'process' => false
                ]);
            }
            exit;
        }

        if ($_POST['type'] == 'editFolder') {

            try {
                $conn->begin_transaction();
                if (!array_key_exists('id', $_POST)) {
                    echo json_encode([
                        'message' => 'No se envio el id del folder',
                        'process' => false
                    ]);
                    exit;
                }

                if (!array_key_exists('nombre', $_POST)) {
                    echo json_encode([
                        'message' => 'El nombre del folder es obligatorio',
                        'process' => false
                    ]);
                    exit;
                }

                $nombre = validateDocumentName($_POST['nombre']);
                $id = $_POST['id'];

                // se buscan todos los ids de los archivos que esten asociados con la carpeta y sus subcarpetas
                $sql = "WITH RECURSIVE CarpetaRuta AS (
                            SELECT 
                                c.id,
                                c.ruta,
                                c.horario_id,
                                c.carpeta_id,
                                a.id AS archivo_id,
                                a.nombre_archivo
                            FROM carpeta c
                            LEFT JOIN archivos a ON c.id = a.carpeta_id
                            WHERE c.id = ?
                            UNION ALL
                            SELECT 
                                c.id,
                                c.ruta,
                                c.horario_id,
                                c.carpeta_id,
                                a.id AS archivo_id,
                                a.nombre_archivo
                            FROM carpeta c
                            LEFT JOIN archivos a ON c.id = a.carpeta_id
                            INNER JOIN CarpetaRuta cr ON c.carpeta_id = cr.id
                                AND c.is_active IS TRUE
                        )
                        SELECT 
                            GROUP_CONCAT(DISTINCT archivo_id ORDER BY archivo_id SEPARATOR ',') AS archivo_id
                        FROM CarpetaRuta;";
                $archivos = ejecutarConsulta($sql, [$id]);

                // obtener la ruta actual de la carpeta
                $sql = "SELECT ruta FROM carpeta WHERE id = ?";
                $oldNameFolder = ejecutarConsulta($sql, [$id]);

                // se obtine la ruta antes de actualizarla de la carpeta
                $oldPathFolder = getPathByFolderId($id, $conn);

                // se actualiza el nombre de la carpeta
                $updateFolder = "UPDATE carpeta SET ruta = ? WHERE id = ?";
                $update = ejecutarConsulta($updateFolder, [$nombre, $id]);
                if ($update) {
                    if ($archivos) {
                        foreach (explode(',', $archivos[0]['archivo_id']) as $value) {
                            $updateFiles = "UPDATE archivos SET ruta = REPLACE(ruta, ?, ?) WHERE id = ?";
                            $resultUpdate = ejecutarConsulta($updateFiles, [$oldNameFolder[0]['ruta'], $nombre, $value]);
                            if (!$resultUpdate) {
                                throw new Exception("Hubo un problema actualizando la carpeta");
                            }
                        }
                    }
                }

                $oldPathFolder = '../horarios/' . $oldPathFolder['ruta'];
                $newPathFolder = str_replace($oldNameFolder[0]['ruta'], $nombre, $oldPathFolder);

                // se valida que el archivo exista dentro del servidor
                if (!file_exists($oldPathFolder)) {
                    throw new Exception("La carpeta no existe dentro del servidor");
                }

                // se renombra el archivo
                if (!rename($oldPathFolder, $newPathFolder)) {
                    throw new Exception("Hubo un error al renombra la carpeta en el servidor");
                }

                echo json_encode([
                    'message' => 'Se actualizo el nombre de la carpeta con exito',
                    'process' => true
                ]);

                $conn->commit();
                $conn->close();
                exit;
            } catch (\Exception $e) {
                $conn->rollback();
                echo json_encode([
                    'message' => $e->getMessage(),
                    'process' => false
                ]);
                $conn->close();
                exit;
            }
        }

        if ($_POST['type'] == 'createFolder') {

            try {
                $nombre = validateDocumentName(trim($_POST['nombre']));
                $id = $_POST['id'];
                $horario_id = $id;
                $isFolder = $_POST['isFolder'];

                if (empty($nombre)) {
                    throw new Exception('El nombre es un campo requerido');
                }

                if (empty($id)) {
                    throw new Exception('El id es un dato requerido');
                }

                if (filter_var($isFolder, FILTER_VALIDATE_BOOLEAN)) {
                    $ruta = getPathByFolderId($id, $conn);
                    $rutaFolder =  '../horarios/' . $ruta['ruta'];
                } else {
                    $sql = "SELECT ruta FROM horarios WHERE id = ?";
                    $resultado = ejecutarConsulta($sql, [$id]);
                    if ($resultado) {
                        $rutaFolder = '../horarios/' . $resultado[0]['ruta'];
                    } else {
                        throw new Exception("El horario no el id <b>$id</b> no existe");
                    }
                }

                // se valida que la ruta exista dentro del servidor
                if (!file_exists($rutaFolder)) {
                    throw new Exception('La ruta no se encuentra dentro del servidor');
                }

                $nuevoFolder = $rutaFolder . '/' . $nombre;
                // se valida que la carpeta no exista dentro del servidor
                if (file_exists($nuevoFolder)) {
                    throw new Exception('La carpeta ya existe dentro del servidor');
                }

                // se valida que se haya podido crear la carpeta con exito
                if (!mkdir($nuevoFolder)) {
                    throw new Exception('Hubo un error al crear la carpeta en el servidor');
                }

                if (filter_var($isFolder, FILTER_VALIDATE_BOOLEAN)) {
                    $sql = "SELECT horario_id FROM carpeta WHERE id = ?";
                    $result = ejecutarConsulta($sql, [$id]);
                    $horario_id = $result[0]['horario_id'];

                    $query = "INSERT INTO carpeta (carpeta_id, ruta, horario_id) VALUES (?,?,?)";
                    $params = [$id, $nombre, $horario_id];
                } else {
                    $query = "INSERT INTO carpeta (ruta, horario_id) VALUES (?,?)";
                    $params = [$nombre, $horario_id];
                }

                $result = ejecutarConsulta($query, $params);
                if (empty($result)) {
                    throw new Exception('Hubo un error al crear la carpeta');
                }

                echo json_encode([
                    'message' => 'Se creo con exito la carpeta',
                    'process' => true
                ]);
                exit;
            } catch (\Exception $e) {
                echo json_encode([
                    'message' => $e->getMessage(),
                    'process' => false
                ]);
                exit;
            }
        }

        if ($_POST['type'] == 'createRectory') {
            try {
                if (!array_key_exists('nombre', $_POST)) {
                    throw new Exception("El campo nombre es obligatorio");
                }
                $nombre = trim($_POST['nombre']);

                if (empty($nombre)) {
                    throw new Exception("El campo nombre no puede ser vacio");
                }


                // validar que alguna rectoria no este creada con el mismo nombre
                $sql = "SELECT * FROM horarios WHERE nombre = ?";
                $resultado = ejecutarConsulta($sql, [$nombre]);
                if ($resultado) {
                    throw new Exception("Ya hay una rectoria creada con el mismo nombre");
                }

                // se crea la rectoria
                $ruta = str_replace(" ", "_", $nombre);
                $sql = "INSERT INTO horarios (nombre, descripcion, ruta) VALUES (?,?, ?);";
                $resultado = ejecutarConsulta($sql, [$nombre, $nombre, $ruta]);
                if (!$resultado) {
                    throw new Exception("Hubo un error al crear la rectoria");
                }

                // se valida que la carpeta no exista dentro del servidor
                if (file_exists('../horarios/' . $ruta)) {
                    throw new Exception("La rectoria ya existe dentro del servidor");
                }

                // se valida que se haya podido crear la carpeta con exito
                if (!mkdir('../horarios/' . $ruta)) {
                    throw new Exception("Hubo un error al crear la rectoria en el servidor");
                }

                echo json_encode([
                    'message' => 'Se creo la rectoria con exito',
                    'process' => true
                ]);
                exit;
            } catch (\Exception $e) {
                echo json_encode([
                    'message' => $e->getMessage(),
                    'process' => false
                ]);
                exit;
            }
        }
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

/**
 * Funcion usada para obtener la ruta completa completa de una carpeta con el id de la carpeta
 */
function getPathByFolderId($id, $conn)
{
    $ruta = $conn->prepare(
        "WITH RECURSIVE CarpetaRuta AS (
            SELECT c.id, c.ruta, c.horario_id, c.carpeta_id
            FROM carpeta c
            INNER JOIN CarpetaRuta cr ON c.id = cr.carpeta_id
            AND c.is_active IS TRUE
            UNION ALL
            SELECT id, ruta, horario_id, carpeta_id
            FROM carpeta
            WHERE id = ?
          )
          SELECT 
            GROUP_CONCAT(ruta ORDER BY id SEPARATOR '/') AS ruta_completa,
            GROUP_CONCAT(id ORDER BY id SEPARATOR '/') AS id_ruta
          FROM CarpetaRuta;",
    );
    $ruta->bind_param("i", $id);
    $ruta->execute();
    $resultado = $ruta->get_result();
    $rest = $resultado->fetch_assoc();

    $pathRoot = getPathHorario($id, true, $conn);
    $path = $rest ? $pathRoot['ruta'] . '/' . $rest['ruta_completa'] : '';

    return [
        'ruta' => $path,
        'rutas_ids' => $rest ? $rest['id_ruta'] : 0
    ];
}

function getPathHorario($id, $byFolder, $conn)
{

    $field = $byFolder ? 'c.id' : 'h.id';
    // consultar la ruta del horario
    $rutaHorario = $conn->prepare(
        "SELECT h.ruta
        FROM horarios h
        LEFT JOIN carpeta c
        ON c.horario_id = h.id
        WHERE $field = ?
        AND c.is_active IS TRUE"
    );
    $rutaHorario->bind_param("i", $id);
    $rutaHorario->execute();
    $rest = $rutaHorario->get_result();
    $resultado = $rest->fetch_assoc();

    return ['ruta' => $resultado ? $resultado['ruta'] : ''];
}

function validateDocumentName($nameFile)
{
    // Reemplazar tildes por letras sin tilde
    $nombre = iconv('UTF-8', 'ASCII//TRANSLIT', $nameFile);

    // Quitar espacios y caracteres especiales
    $nombre = preg_replace('/\s+/', '_', $nombre); // Quitar espacios en blanco
    $nombre = preg_replace('/[^\w.-]/', '', $nombre); // Quitar caracteres especiales excepto punto (.) y guion (-)

    return $nombre;
}


function validateFile($id, $fileName, $targetFile, $isFolder, $conn)
{
    $field = filter_var($isFolder, FILTER_VALIDATE_BOOLEAN) ? 'carpeta_id' : 'horario_id';
    $sql = "SELECT
            *
            FROM archivos 
            WHERE $field = ?
            AND nombre_archivo = ?
            AND ruta = ?
            AND is_active IS TRUE";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sss", $id, $fileName, $targetFile);
    $stmt->execute();
    $resultadoArchivos = $stmt->get_result();
    return $resultadoArchivos->fetch_assoc();
}


function saveFile($id, $fileName, $targetFile, $isFolder, $conn)
{
    $field = filter_var($isFolder, FILTER_VALIDATE_BOOLEAN) ? 'carpeta_id' : 'horario_id';
    $queryInsertFile = "INSERT INTO archivos (ruta, nombre_archivo, $field) VALUES(?,?,?);";
    $stmt = $conn->prepare($queryInsertFile);
    $stmt->bind_param("sss", $targetFile, $fileName, $id);

    return $stmt->execute();
}
