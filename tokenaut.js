const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const helmet = require('helmet'); // Encabezados de seguridad HTTP
const csrf = require('csurf'); // Protección contra ataques CSRF
const cookieParser = require('cookie-parser');
const db = require('./conexionDB/db'); // Configuración de la base de datos

const app = express();

// Middleware globales
app.use(express.json());
app.use(helmet());
app.use(cookieParser()); // Para manejar cookies

// Configuración del middleware CSRF
const csrfProtection = csrf({
    cookie: {
        httpOnly: true, // Hace que las cookies no sean accesibles desde el frontend
        secure: process.env.NODE_ENV === 'production', // Solo cookies seguras en producción
        sameSite: 'strict', // Cookies enviadas solo al mismo dominio
    },
});
app.use(csrfProtection); // Aplicar protección CSRF a las rutas necesarias

// Generar el token CSRF
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Clave secreta JWT (preferiblemente configurar con variables de entorno)
const secretKey = process.env.JWT_SECRET || 'kerberos';

// Middleware para verificar JWT
function authenticateToken(req, res, next) {
    const authHeader = req.header('Authorization');
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Acceso denegado' });
    }

    try {
        const verified = jwt.verify(token, secretKey);
        req.user = verified;
        next();
    } catch (err) {
        if (err.name === 'JsonWebTokenError') {
            return res.status(400).json({ message: 'Token no válido' });
        } else {
            console.error('Error inesperado:', err); // Log para depuración
            return res.status(500).json({ message: 'Error del servidor' });
        }
    }
}

// Ruta para registrar usuarios
app.post('/register', async (req, res) => {
    const { email, password } = req.body;

    // Validar campos
    if (!email || !password) {
        return res.status(400).json({ message: 'Todos los campos deben ser completados' });
    }

    try {
        // Validar si el email ya está registrado
        const existingUser = await db.query('SELECT * FROM register WHERE email = $1', [email]);
        if (existingUser.rows.length > 0) {
            return res.status(400).json({ message: `${email} ya está registrado` });
        }

        // Cifrar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insertar usuario en la base de datos
        await db.query('INSERT INTO register (email, password) VALUES ($1, $2)', [email, hashedPassword]);
        res.status(201).json({ message: `Usuario ${email} registrado exitosamente` });
    } catch (error) {
        console.error('Error al registrar usuario:', error);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

// Ruta de login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Todos los campos deben ser completados' });
    }

    try {
        // Buscar usuario
        const user = await db.query('SELECT * FROM register WHERE email = $1', [email]);
        if (user.rows.length === 0) {
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }

        // Verificar la contraseña
        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) {
            return res.status(400).json({ message: 'Contraseña incorrecta' });
        }

        // Generar el token JWT
        const token = jwt.sign({ userId: user.rows[0].id }, secretKey, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

// Ruta protegida: Obtener usuarios (requiere JWT)
app.get('/users', authenticateToken, async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM register');
        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error al obtener usuarios:', error);
        res.status(500).json({ message: 'Error del servidor' });
    }
});

// Seguridad adicional: Validar el origen de las solicitudes
app.use((req, res, next) => {
    const allowedOrigins = ['http://localhost:3000', 'https://tudominio.com'];
    const origin = req.get('Origin');
    if (origin && !allowedOrigins.includes(origin)) {
        return res.status(403).json({ message: 'Origen no permitido' });
    }
    next();
});

// Escuchar en el puerto configurado
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Servidor corriendo en el puerto ${PORT}`);
});
