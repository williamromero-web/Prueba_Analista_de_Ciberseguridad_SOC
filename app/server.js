/**
 * ===========================================================================
 *  FleetSec API - versión vulnerable para el laboratorio
 * ===========================================================================
 *
 *  Aplicación mínima en Node.js y Express que reproduce, de forma controlada,
 *  las 10 fallas de seguridad que se analizan en la prueba.
 *
 *  ATENCION: este archivo tiene errores de seguridad puestos a propósito. Sirve
 *  como blanco de las pruebas de penetración y para comprobar que el pipeline
 *  los detecta y bloquea. No debe ejecutarse en un entorno real.
 *
 *  La versión corregida es la que queda al final en app/server.js. Esta versión
 *  se conserva en la carpeta _vulnerable_baseline, que el pipeline ignora.
 * ===========================================================================
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const axios = require('axios');
const fs = require('fs');
const { DOMParser } = require('xmldom');
const xpath = require('xpath');

const app = express();
app.use(express.json());
app.use(express.text({ type: 'application/xml' }));

// ---------------------------------------------------------------------------
// V-10 · Credenciales escritas en el código
// Los secretos están dentro del archivo fuente. Gitleaks debe encontrarlos y
// detener el pipeline. Se usan las claves de ejemplo que pública AWS.
// ---------------------------------------------------------------------------
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const JWT_SECRET = "super_secret_key";
const DB_PASSWORD = "P@ssw0rd_Fleet_2024!";

// ---------------------------------------------------------------------------
// Base de datos en memoria con datos de prueba. Incluye correo y cédula
// simulados para poder demostrar el registro de datos personales en los logs.
// ---------------------------------------------------------------------------
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, cc TEXT, role TEXT)");
    db.run("INSERT INTO users (username, password, email, cc, role) VALUES ('admin', 'admin123', 'admin@fleetsec.com', '123456789', 'admin')");
    db.run("INSERT INTO users (username, password, email, cc, role) VALUES ('user', 'user123', 'user@fleetsec.com', '987654321', 'user')");
});

// ---------------------------------------------------------------------------
// POST /api/login
// Concentra tres fallas a propósito:
//   V-07 · Sin limite de intentos, queda expuesto a fuerza bruta.
//   V-01 · Inyección SQL, la consulta se arma pegando lo que envia el usuario.
//   V-08 · Registro de datos personales, imprime correo y cédula en el log.
// ---------------------------------------------------------------------------
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    // V-01: consulta armada por concatenación, se puede inyectar con ' OR '1'='1
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.get(query, (err, user) => {
        if (err || !user) return res.status(401).send("Error");
        // V-08: escribe datos personales en texto plano en el log del servidor
        console.log(`[INFO] Login - Usuario: ${user.username}, Email: ${user.email}, Cédula: ${user.cc}`);
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET);
        res.json({ token });
    });
});

// ---------------------------------------------------------------------------
// Middleware de autenticación
// V-02 · Sesión rota. Usa jwt.decode en lugar de jwt.verify, así que no
// comprueba la firma. Un token falsificado con el algoritmo none se acepta
// como si fuera válido.
// ---------------------------------------------------------------------------
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).send("Token requerido");
    try {
        req.user = jwt.decode(token); // V-02: decodifica sin comprobar la firma
        next();
    } catch (err) {
        res.status(401).send("Error");
    }
};

// ---------------------------------------------------------------------------
// GET /api/proxy?url=
// V-03 · El servidor consulta cualquier dirección que le indique el usuario,
// sin validarla. Permite alcanzar recursos internos como el servicio de
// metadatos de la nube en 169.254.169.254.
// ---------------------------------------------------------------------------
app.get('/api/proxy', authMiddleware, async (req, res) => {
    try {
        const response = await axios.get(req.query.url);
        res.send(response.data);
    } catch (err) {
        res.status(500).send("Error SSRF");
    }
});

// ---------------------------------------------------------------------------
// GET /api/users/:id
// V-09 · Cualquier usuario autenticado puede leer el perfil de otro con solo
// cambiar el id, porque no se comprueba a quien pertenece el dato.
// V-01 · El id se pega directamente dentro de la consulta.
// ---------------------------------------------------------------------------
app.get('/api/users/:id', authMiddleware, (req, res) => {
    db.get(`SELECT username, email, role FROM users WHERE id = ${req.params.id}`, (err, user) => {
        if (err || !user) return res.status(404).send("Not found");
        res.json(user);
    });
});

// ---------------------------------------------------------------------------
// POST /api/xml-upload
// V-04 · El procesamiento de XML resuelve entidades externas, lo que permite
// leer archivos del servidor y sacarlos en la respuesta. La expansión se hace
// aquí a mano para reproducir el comportamiento de un lector de XML inseguro.
// ---------------------------------------------------------------------------
app.post('/api/xml-upload', (req, res) => {
    try {
        let payload = req.body;
        // Comportamiento vulnerable: resuelve entidades externas de tipo file
        const entity = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"file:\/\/([^"]+)"\s*>/i.exec(payload);
        if (entity) {
            const [, name, path] = entity;
            const fileContent = fs.readFileSync(path.replace(/^\/+/, ''), 'utf8');
            payload = payload.replace(new RegExp(`&${name};`, 'g'), fileContent);
        }
        const doc = new DOMParser().parseFromString(payload, 'text/xml');
        const username = xpath.select('string(//username)', doc) || 'Anónimo';
        res.send(`XML Procesado. Hola, ${username}`);
    } catch (e) {
        res.status(400).send("XML Inválido");
    }
});

// ---------------------------------------------------------------------------
// POST /api/users/update
// V-05 · Asignación masiva. Mezcla todo el contenido enviado por el usuario
// con su registro, así que basta con mandar el campo role para volverse
// administrador.
// ---------------------------------------------------------------------------
app.post('/api/users/update', authMiddleware, (req, res) => {
    const userId = req.user.id;
    db.get(`SELECT * FROM users WHERE id = ${userId}`, (err, user) => {
        if (err || !user) return res.status(404).send("Not found");
        // V-05: se aceptan todos los campos enviados, incluido role
        const updatedUser = Object.assign({}, user, req.body);
        const updateQuery = `UPDATE users SET username='${updatedUser.username}', email='${updatedUser.email}', role='${updatedUser.role}' WHERE id=${userId}`;
        db.run(updateQuery, (err) => {
            if (err) return res.status(500).send("Error actualizando DB");
            res.json(updatedUser);
        });
    });
});

// ---------------------------------------------------------------------------
// GET /api/files?file=
// V-06 · Pega el nombre del archivo sin revisarlo, así que con ../ se puede
// salir de la carpeta docs y leer otros archivos del servidor.
// ---------------------------------------------------------------------------
app.get('/api/files', (req, res) => {
    const filename = req.query.file;
    try {
        const data = fs.readFileSync('./docs/' + filename, 'utf8');
        res.send(data);
    } catch (e) {
        res.status(404).send("File not found");
    }
});

// Se expone en 0.0.0.0 para que el escaner dinámico pueda alcanzar la API.
app.listen(3000, '0.0.0.0', () => console.log("Servidor escuchando en 0.0.0.0:3000"));
