const express = require('express');
const db = require('./db');

const app = express();
app.use(express.json());

// Ruta de ejemplo para obtener usuarios
app.get('/users', async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM register');
    res.status(200).json(result.rows);
  } catch (error) {
    res.status(500).send('Server error');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
