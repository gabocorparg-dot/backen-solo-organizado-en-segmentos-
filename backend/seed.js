// Este script es para poblar la base de datos con datos iniciales.

// Cargar módulos
require('dotenv').config(); // Lee el archivo .env
const mysql = require('mysql2');
const bcrypt = require('bcryptjs'); // Para cifrar contraseñas

// Configurar conexión a la BD

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    multipleStatements: true 
});

// Función principal para poblar
async function poblarDatos() {
    try {
        await db.promise().connect();
        console.log('Conectado a la BD para poblar datos...');

        // Crear Usuarios 

        // Ciframos las claves ANTES de guardarlas

        const claveAdminCifrada = await bcrypt.hash('admin123', 10);
        const claveProfeCifrada = await bcrypt.hash('prof123', 10);

        const consultaUsuarios = `
        INSERT IGNORE INTO usuarios (email, nombre, clave, rol) VALUES 
        ('admin@colegio.edu', 'Administrador', ?, 'ADMIN'),
        ('profe@colegio.edu', 'Profesor Juan', ?, 'PROFESOR');
        `;
        
        await db.promise().query(consultaUsuarios, [claveAdminCifrada, claveProfeCifrada]);
        console.log('Usuarios (admin, profe) creados.');

        // Crear Materias
        const consultaMaterias = `
        INSERT IGNORE INTO materias (nombre) VALUES
        ('Matemáticas'), ('Inglés Técnico'), ('Marco Jurídico y Derechos del Trabajador'),
        ('Asistencia 2'), ('Hardware 4'), ('Prácticas Profesionalizantes 2'),
        ('Programación 4'), ('Redes 3');
        `;
        
        await db.promise().query(consultaMaterias);
        console.log('Materias creadas.');
        
        console.log('¡Poblado de datos completado!');

    } catch (error) {
        console.error('Error poblando la base de datos:', error);
    } finally {
        db.end(); // Cerrar la conexión
    }
}

// Ejecutar la función
poblarDatos();