const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('./conexionDB/db');

const app = express();
app.use(express.json());

// Ruta para obtener usuarios
app.get('/users', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM register');
    res.status(200).json(result.rows);
  } catch (error) {
    res.status(500).send('Server error');
  }
});

// Ruta para agregar usuarios
app.post('/users', async (req, res) =>{
  const { email, password } = req.body;

  // Cifrar contraseña
  const result = await db.query('INSERT INTO register (email, password) VALUES ($1, $2) RETURNING *', [email, password]);
  res.status(201).json(result.rows[0]);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
