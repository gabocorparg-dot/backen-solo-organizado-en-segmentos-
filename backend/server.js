
/*CARGA DE MÓDULOS*/

require("dotenv").config();
const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

/*INICIALIZACIÓN Y CONEXIÓN BD*/

const app = express();
app.use(cors()); 
app.use(express.json()); 

// Creamos un Pool de conexiones a la BD (más eficiente)
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise(); // Habilitamos promesas (await)


// Verifica la conexión al iniciar

db.getConnection()
    .then(connection => {
        console.log("Conectado exitosamente a la base de datos MySQL (boletin_db).");
        connection.release();
    })
    .catch(error => {
        console.error("Error al conectar a MySQL:", error);
    });



/*MIDDLEWARE (Verificadores)*/

//verifica el Token

function verificarToken(req, res, next) {
    const cabecera = req.headers["authorization"]; 
    if (!cabecera) return res.status(403).json({ message: "No se proveyó un token." });

    const token = cabecera.split(" ")[1];
    if (!token) return res.status(403).json({ message: "Token mal formado." });

    try {
        const decodificado = jwt.verify(token, process.env.JWT_SECRETO);
        req.usuario = decodificado; // Adjuntamos los datos del usuario (id, rol) al request
        next(); 
    } catch (error) {
        return res.status(401).json({ message: "Token inválido o expirado." });
    }
}

//verifica si el rol es ADMIN

function esAdmin(req, res, next) {
    if (req.usuario.rol !== "ADMIN") {
        return res.status(403).json({ message: "Acceso denegado. Se requiere rol de ADMIN." });
    }
    next();
}

//verifica si el rol es ADMIN o PROFESOR

function esAdminOProfe(req, res, next) {
    if (req.usuario.rol !== "ADMIN" && req.usuario.rol !== "PROFESOR") {
         return res.status(403).json({ message: "Acceso denegado. Se requiere rol de ADMIN o PROFESOR." });
    }
    next();
}

/*RUTAS DE AUTENTICACIÓN*/

// POST /api/login (Ruta pública)
app.post("/api/login", async (req, res) => {
    const { email, clave } = req.body;
    if (!email || !clave) {
        return res.status(400).json({ message: "Email y clave son requeridos." });
    }
    try {
        const sql = "SELECT * FROM usuarios WHERE email = ?";
        const [resultados] = await db.query(sql, [email]); 
        
        if (resultados.length === 0) {
            return res.status(401).json({ message: "Correo o clave incorrectos." });
        }
        
        const usuario = resultados[0];
        const claveEsValida = await bcrypt.compare(clave, usuario.clave);
        
        if (!claveEsValida) {
            return res.status(401).json({ message: "Correo o clave incorrectos." });
        }

        const token = jwt.sign({ id: usuario.id, rol: usuario.rol }, process.env.JWT_SECRETO, { expiresIn: "1h" });
        delete usuario.clave;
        res.status(200).json({ message: "Login exitoso", token: token, usuario: usuario });

    } catch (err) {
        res.status(500).json({ message: "Error del servidor.", error: err });
    }
});

/*RUTAS DE USUARIOS (CRUD)*/

// GET /api/usuarios (Solo Admin)

app.get("/api/usuarios", [verificarToken, esAdmin], async (req, res) => {
    try {
        const sql = "SELECT id, email, nombre, rol, curso FROM usuarios";
        const [resultados] = await db.query(sql); 
        res.status(200).json({ usuarios: resultados });
    } catch (err) {
        res.status(500).json({ message: "Error del servidor.", error: err });
    }
});

// GET /api/alumnos (Admin y Profesor)

app.get("/api/alumnos", [verificarToken, esAdminOProfe], async (req, res) => {
    try {
        const sql = "SELECT id, email, nombre, rol, curso FROM usuarios WHERE rol = 'ALUMNO'";
        const [resultados] = await db.query(sql); 
        res.status(200).json({ alumnos: resultados });
    } catch (err) {
        res.status(500).json({ message: "Error del servidor.", error: err });
    }
});

// POST /api/usuarios (Solo Admin)

app.post("/api/usuarios", [verificarToken, esAdmin], async (req, res) => {
    const { nombre, email, clave, rol, curso } = req.body;
    if (!nombre || !email || !clave || !rol) {
        return res.status(400).json({ message: "Todos los campos (nombre, email, clave, rol) son requeridos." });
    }
    try {
        const claveCifrada = await bcrypt.hash(clave, 10);
        const sql = "INSERT INTO usuarios (nombre, email, clave, rol, curso) VALUES (?, ?, ?, ?, ?)";
        await db.query(sql, [nombre, email, claveCifrada, rol.toUpperCase(), curso || null]); 
        res.status(201).json({ message: "Usuario creado exitosamente." });
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ message: "Error: El email ya está en uso." });
        }
        res.status(500).json({ message: "Error del servidor.", error: error });
    }
});

// PUT /api/usuarios/me (Cualquier rol logueado - "Mis Datos")

app.put("/api/usuarios/me", [verificarToken], async (req, res) => {
    const { id } = req.usuario; 
    const { nombre, email, clave } = req.body;
    if (!nombre || !email) {
        return res.status(400).json({ message: "Nombre y email son requeridos." });
    }
    try {
        if (clave) {
            const claveCifrada = await bcrypt.hash(clave, 10);
            const sql = "UPDATE usuarios SET nombre = ?, email = ?, clave = ? WHERE id = ?";
            await db.query(sql, [nombre, email, claveCifrada, id]); 
        } else {
            const sql = "UPDATE usuarios SET nombre = ?, email = ? WHERE id = ?";
            await db.query(sql, [nombre, email, id]); 
        }
        const [rows] = await db.query("SELECT id, email, nombre, rol, curso FROM usuarios WHERE id = ?", [id]); 
        res.status(200).json({ message: "Datos actualizados exitosamente.", usuario: rows[0] });
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ message: "Error: El email ya está en uso por otra cuenta." });
        }
        res.status(500).json({ message: "Error del servidor.", error: error });
    }
});

// PUT /api/usuarios/:id (Solo Admin)

app.put("/api/usuarios/:id", [verificarToken, esAdmin], async (req, res) => {
    const { id } = req.params;
    const { nombre, email, clave, rol, curso } = req.body;
    if (!nombre || !email || !rol) {
        return res.status(400).json({ message: "Nombre, email y rol son requeridos." });
    }
    try {
        if (clave) {
            const claveCifrada = await bcrypt.hash(clave, 10);
            const sql = "UPDATE usuarios SET nombre = ?, email = ?, clave = ?, rol = ?, curso = ? WHERE id = ?";
            await db.query(sql, [nombre, email, claveCifrada, rol.toUpperCase(), curso || null, id]); 
        } else {
            const sql = "UPDATE usuarios SET nombre = ?, email = ?, rol = ?, curso = ? WHERE id = ?";
            await db.query(sql, [nombre, email, rol.toUpperCase(), curso || null, id]); 
        }
        res.status(200).json({ message: "Usuario actualizado exitosamente." });
    } catch (error) {
        if (error.code === "ER_DUP_ENTRY") {
            return res.status(409).json({ message: "Error: El email ya está en uso." });
        }
        res.status(500).json({ message: "Error del servidor.", error: error });
    }
});

// DELETE /api/usuarios/:id (Solo Admin)

app.delete("/api/usuarios/:id", [verificarToken, esAdmin], async (req, res) => {
    const { id } = req.params;
    if (parseInt(id) === req.usuario.id) {
         return res.status(400).json({ message: "No puedes eliminar tu propia cuenta de administrador." });
    }
    try {
        const sql = "DELETE FROM usuarios WHERE id = ?";
        await db.query(sql, [id]); 
        res.status(200).json({ message: "Usuario eliminado exitosamente." });
    } catch (error) {
        res.status(500).json({ message: "Error del servidor.", error: error });
    }
});


/* RUTAS DE BOLETINES */

// GET /api/boletin/me (Ruta para el Alumno logueado)

app.get("/api/boletin/me", [verificarToken], async (req, res) => {
    const { id } = req.usuario; 
    try {
        const sql = `
            SELECT 
                m.id AS materiaId, m.nombre AS materiaNombre,
                n.id AS notaId,
                n.informe1, n.informe2, n.cuatri1,
                n.informe1_c2, n.informe2_c2, n.cuatri2,
                n.rec_dic, n.rec_feb, n.nota_final
            FROM materias m
            LEFT JOIN notas n ON m.id = n.materiaId AND n.alumnoId = ?
        `;
        const [boletin] = await db.query(sql, [id]);
        res.status(200).json({ boletin: boletin });
    } catch (error) {
        res.status(500).json({ message: "Error del servidor.", error: error });
    }
});

// GET (Admin y Profesor)

app.get("/api/boletin/:id", [verificarToken, esAdminOProfe], async (req, res) => {
    const { id } = req.params; // ID del alumno
    try {
        const sql = `
            SELECT 
                m.id AS materiaId, m.nombre AS materiaNombre,
                n.id AS notaId,
                n.informe1, n.informe2, n.cuatri1,
                n.informe1_c2, n.informe2_c2, n.cuatri2,
                n.rec_dic, n.rec_feb, n.nota_final
            FROM materias m
            LEFT JOIN notas n ON m.id = n.materiaId AND n.alumnoId = ?
        `;
        const [boletin] = await db.query(sql, [id]); 
        res.status(200).json({ boletin: boletin });
    } catch (error) {
        res.status(500).json({ message: "Error del servidor.", error: error });
    }
});

// POST (Admin y Profesor - Guardar Notas)

app.post("/api/boletin", [verificarToken, esAdminOProfe], async (req, res) => {
    const { alumnoId, notas } = req.body; 
    if (!alumnoId || !notas || !Array.isArray(notas)) {
        return res.status(400).json({ message: "Se requiere \"alumnoId\" y un array de \"notas\"." });
    }
    
    let connection;
    try {
        connection = await db.getConnection(); 
        await connection.beginTransaction();

        const sql = `
            INSERT INTO notas (
                alumnoId, materiaId, informe1, informe2, cuatri1, 
                informe1_c2, informe2_c2, cuatri2, rec_dic, rec_feb, nota_final
            ) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                informe1 = VALUES(informe1), informe2 = VALUES(informe2), cuatri1 = VALUES(cuatri1),
                informe1_c2 = VALUES(informe1_c2), informe2_c2 = VALUES(informe2_c2), cuatri2 = VALUES(cuatri2),
                rec_dic = VALUES(rec_dic), rec_feb = VALUES(rec_feb), nota_final = VALUES(nota_final)
        `;

        for (const nota of notas) {
            await connection.query(sql, [
                alumnoId, nota.materiaId,
                nota.informe1 || "", nota.informe2 || "", nota.cuatri1 || "",
                nota.informe1_c2 || "", nota.informe2_c2 || "", nota.cuatri2 || "",
                nota.rec_dic || "", nota.rec_feb || "", nota.nota_final || ""
            ]);
        }
        
        await connection.commit();
        res.status(200).json({ message: "Boletín guardado exitosamente." });

    } catch (error) {
        if (connection) await connection.rollback(); 
        res.status(500).json({ message: "Error al guardar el boletín.", error: error });
    } finally {
        if (connection) connection.release(); 
    }
});

/* INICIO DEL SERVIDOR */

const PUERTO = 3000; 
app.listen(PUERTO, () => {
    console.log(`Servidor backend corriendo en http://localhost:${PUERTO}`);
});