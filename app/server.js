/**
 * ===========================================================================
 *  FleetSec API - versión corregida
 * ===========================================================================
 *
 *  Esta es la versión que el pipeline analiza y despliega. Corrige las 10
 *  fallas encontradas sin quitar ningún endpoint: cada ruta conserva su
 *  función normal pero rechaza los intentos maliciosos.
 *
 *  La versión vulnerable original se conserva, como referencia, en
 *  _vulnerable_baseline/app/server.js, que el pipeline ignora.
 * ===========================================================================
 */

const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const jwt = require('jsonwebtoken');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const rateLimit = require('express-rate-limit');
// Se usa la versión mantenida del lector de XML. El paquete anterior esta
// descontinuado y arrastraba fallas conocidas sin arreglo.
const { DOMParser } = require('@xmldom/xmldom');
const xpath = require('xpath');

const app = express();
app.use(express.json());
app.use(express.text({ type: 'application/xml' }));

// ---------------------------------------------------------------------------
// Cabeceras de seguridad básicas. Son una capa extra de protección y reducen
// los avisos que levanta el escaneo dinámico.
// ---------------------------------------------------------------------------
app.disable('x-powered-by');
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
});

// ---------------------------------------------------------------------------
// V-10 corregido · Credenciales fuera del código
// El secreto de sesión se toma solo de una variable de entorno. No queda
// ningún secreto escrito en el código fuente. En producción lo entrega el
// gestor de secretos.
// ---------------------------------------------------------------------------
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
    console.error('[FATAL] Falta la variable de entorno JWT_SECRET');
    process.exit(1);
}

// ---------------------------------------------------------------------------
// V-08 corregido · Enmascarado de datos personales
// Toda la aplicación escribe sus registros a través de logSafe, que oculta
// cualquier dato personal antes de que llegue al log.
// ---------------------------------------------------------------------------
const PII_KEYS = new Set(['email', 'correo', 'cc', 'cedula', 'cédula', 'telefono', 'teléfono', 'direccion', 'dirección', 'password']);
const maskValue = (s) => (s.length <= 4 ? '****' : s.slice(0, 2) + '****' + s.slice(-2));
function redactPII(meta) {
    const out = {};
    for (const [k, v] of Object.entries(meta || {})) {
        out[k] = PII_KEYS.has(k.toLowerCase()) ? maskValue(String(v)) : v;
    }
    return out;
}
function logSafe(level, msg, meta) {
    // Único punto que escribe en consola. Los datos ya llegan enmascarados.
    console[level](`[${level.toUpperCase()}] ${msg} ${JSON.stringify(redactPII(meta))}`);
}

// ---------------------------------------------------------------------------
// Base de datos en memoria con datos de prueba.
// ---------------------------------------------------------------------------
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, cc TEXT, role TEXT)");
    db.run("INSERT INTO users (username, password, email, cc, role) VALUES ('admin', 'admin123', 'admin@fleetsec.com', '123456789', 'admin')");
    db.run("INSERT INTO users (username, password, email, cc, role) VALUES ('user', 'user123', 'user@fleetsec.com', '987654321', 'user')");
});

// Comprobación de estado. La usan el contenedor y el escaner para saber que
// la API esta viva.
app.get('/', (req, res) => res.send('FleetSec API - Staging'));

// ---------------------------------------------------------------------------
// V-07 corregido · Limite de intentos
// Frena los ataques de fuerza bruta contra el inicio de sesión.
// ---------------------------------------------------------------------------
const loginLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // ventana de 5 minutos
    max: 5,                   // 5 intentos por dirección dentro de la ventana
    standardHeaders: true,
    legacyHeaders: false,
    message: 'Demasiados intentos de inicio de sesión, intente más tarde.',
});

// ---------------------------------------------------------------------------
// POST /api/login
// V-01 corregido · La consulta usa parámetros, ya no se arma pegando texto.
// V-08 corregido · El registro pasa por el enmascarado de datos personales.
// V-02 corregido · El token se firma indicando el algoritmo de forma explicita.
// ---------------------------------------------------------------------------
app.post('/api/login', loginLimiter, (req, res) => {
    const { username, password } = req.body;
    const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
    db.get(query, [username, password], (err, user) => {
        if (err) return res.status(500).send('Error interno');
        if (!user) return res.status(401).send('Credenciales inválidas');
        // El enmascarado oculta correo y cédula antes de escribir en el log.
        logSafe('info', 'Login exitoso', { userId: user.id, email: user.email, cc: user.cc });
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { algorithm: 'HS256' });
        res.json({ token });
    });
});

// ---------------------------------------------------------------------------
// V-02 corregido · Middleware de autenticación
// Comprueba la firma del token y acepta un solo algoritmo, así que un token
// falsificado sin firma queda rechazado.
// ---------------------------------------------------------------------------
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(403).send('Token requerido');
    try {
        req.user = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
        next();
    } catch (err) {
        res.status(401).send('Token inválido');
    }
};

// ---------------------------------------------------------------------------
// GET /api/proxy?target=
// V-03 corregido · El usuario ya no envia una dirección, sino que elige una
// opcion de una lista cerrada. La dirección real que se consulta es siempre
// una constante del servidor, así que lo que escribe el usuario nunca llega
// a la petición de salida.
// ---------------------------------------------------------------------------
async function fetchConstant(url, res) {
    try {
        const response = await axios.get(url, { timeout: 5000, maxRedirects: 0 });
        res.send(response.data);
    } catch (err) {
        res.status(502).send('Error consultando el recurso permitido');
    }
}
app.get('/api/proxy', authMiddleware, (req, res) => {
    switch (req.query.target) {
        case 'github':
            return fetchConstant('https://api.github.com', res);
        case 'status':
            return fetchConstant('https://jsonplaceholder.typicode.com/todos/1', res);
        default:
            return res.status(403).send('Destino no permitido por la política de seguridad');
    }
});

// ---------------------------------------------------------------------------
// GET /api/users/:id
// V-09 corregido · Solo el propio usuario o un administrador pueden ver el
// perfil. V-01 corregido · El identificador viaja como parámetro.
// ---------------------------------------------------------------------------
app.get('/api/users/:id', authMiddleware, (req, res) => {
    if (String(req.user.id) !== String(req.params.id) && req.user.role !== 'admin') {
        return res.status(403).send('Acceso denegado a los datos de otro usuario');
    }
    db.get('SELECT username, email, role FROM users WHERE id = ?', [req.params.id], (err, user) => {
        if (err || !user) return res.status(404).send('No encontrado');
        res.json(user);
    });
});

// ---------------------------------------------------------------------------
// POST /api/xml-upload
// V-04 corregido · Se rechaza cualquier declaración de entidades, con lo que
// ya no se pueden leer archivos del servidor. El XML normal se sigue
// procesando igual que antes.
// ---------------------------------------------------------------------------
app.post('/api/xml-upload', (req, res) => {
    const payload = req.body || '';
    if (/<!DOCTYPE|<!ENTITY/i.test(payload)) {
        return res.status(400).send('Declaraciones DOCTYPE/ENTITY no permitidas');
    }
    try {
        const doc = new DOMParser().parseFromString(payload, 'text/xml');
        const username = xpath.select('string(//username)', doc) || 'Anónimo';
        res.send(`XML Procesado. Hola, ${username}`);
    } catch (e) {
        res.status(400).send('XML inválido');
    }
});

// ---------------------------------------------------------------------------
// POST /api/users/update
// V-05 corregido · Solo se aceptan los campos permitidos, que son el nombre de
// usuario y el correo. El campo de rol enviado por el usuario se descarta.
// ---------------------------------------------------------------------------
app.post('/api/users/update', authMiddleware, (req, res) => {
    const userId = req.user.id;
    const { username, email } = req.body; // el rol nunca se acepta del usuario
    db.run('UPDATE users SET username = ?, email = ? WHERE id = ?', [username, email, userId], function (err) {
        if (err) return res.status(500).send('Error actualizando');
        res.json({ id: userId, username, email });
    });
});

// ---------------------------------------------------------------------------
// GET /api/files?file=
// V-06 corregido · La ruta se resuelve por completo y se comprueba que siga
// dentro de la carpeta docs. Cualquier intento de subir de nivel queda fuera.
// ---------------------------------------------------------------------------
const DOCS_DIR = path.resolve(__dirname, 'docs');
app.get('/api/files', (req, res) => {
    const requested = path.resolve(DOCS_DIR, req.query.file || '');
    if (requested !== DOCS_DIR && !requested.startsWith(DOCS_DIR + path.sep)) {
        return res.status(400).send('Ruta inválida');
    }
    try {
        res.send(fs.readFileSync(requested, 'utf8'));
    } catch (e) {
        res.status(404).send('Archivo no encontrado');
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => logSafe('info', `Servidor escuchando en 0.0.0.0:${PORT}`, {}));
