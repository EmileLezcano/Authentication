const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./conexionDB/db');

const app = express();
app.use(express.json());

// Ruta para obtener usuarios
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM register');
    res.status(200).json(result.rows);
  } catch (error) {
    console.error(error); // Agregar log de error para depuración
    res.status(500).json({ message: 'Server error' });
  }
});

// Ruta para agregar usuarios
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Validar que se completen todos los campos
  if (!email || !password) {
    return res.status(400).json({ message: 'Todos los campos se deben completar' });
  }

  try {
    // Validar que el email no se repita
    const verificarEmail = await db.query('SELECT * FROM register WHERE email = $1', [email]);
    if (verificarEmail.rows.length > 0) {
      return res.status(400).json({ message: `${email} ya se encuentra registrado` });
    }

    // Cifrar contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insertar usuario
    const result = await db.query('INSERT INTO register (email, password) VALUES ($1, $2) RETURNING *', [email, hashedPassword]);
    res.status(201).json({ message: `Usuario ${email} registrado con éxito` });
  } catch (error) {
    console.error(error); // Agregar log de error para depuración
    res.status(500).json({ message: 'Server error' });
  }
});

// clave secreta JWT 
const secretKey = 'kerberos';

// Ruta de login: Esta ruta autentica a los usuarios registrados y genera un token JWT que se les enviará.
app.post('/login', async (req, res)=>{
  const { email, password } = req.body;

  // Validar que se completen todos los campos
  if (!email || !password) {
    return res.status(400).json({ message: 'Todos los campos se deben completar'});
  }
  
  try {
    // Buscar usuario en la base de datos
    const user = await db.query('SELECT * FROM register WHERE email = $1', [email]);

    // Verificar si el usuario existe
    if (user.rows.length === 0) {
      return res.status(400).json({ message: 'Usuario no encontrado'});
    }
    
    // Comprobar contraseña
    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(400).json({ message: 'Contraseña incorrecta'});
    }

    // Generar el token JWT
    const token = jwt.sign({ userId: user.rows[0].id }, secretKey, { expiresIn: '1h'});
    res.json({ token });
  
  } catch (error) {
    console.error(error); // Agregar log de error para depuración
    res.status(500).json({ message: 'Server error'});
  }
});

// Middleware para verificar JWT
function authenticateToken (req, res, next) {
  const token = req.header('Authorization')?.replace('Bearer', '');
  if (!token) {
    return res.status(401).json({ message: 'Acceso denegado'});
  }

  try {
    const verified = jwt.verify(token, secretKey);
    req.user = verified;
    next();
  } catch (err) {

    if (err.name === 'JsonWebTokenError') {
      return res.status(400).json({ message: 'Token no valido'});
    } else {
      console.error('Error inesperado:', err);  // Agregar log de error para depuración
      return res.status(500).json({ message: 'Server error'});
    }
    
  }
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});