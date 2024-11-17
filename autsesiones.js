// const express = require('express');
// const session = require('express-session');

// const app = express();

// // Middleware para analizar JSON
// app.use(express.json());

// const user = [
//     { id: 1, email: 'john@example.com', password: '123' },
//     { id: 2, email: 'jane@example.com', password: 456 }
// ]

// // Middleware setup
// app.use(session({
//     secret: 'kerberos',
//     resave: false, // resave: volver a guardar
//     saveUninitialized: false, // saveUninitialized: guardar sin inicializar
//     cookie: {
//         httpOnly: true, // establecer la cookie como solo HTTP.
//         secure: false, // establecer la cookie como solo HTTPS en este caso aun esta en falso.
//         //maxAge: 3600000 // establecer la cookie para que expire en 1 hora
//         //maxAge: 60*30 // en segundos
//         maxAge: 300000 // 5 minutos en milisegundos
//     }
// }));

// // Ruta de inicio
// app.post('/log', (req, res) => {
//     // requerir parametros desde el cuerpo de la solicitud
//     const { email, password } = req.body;

//     // busco al usuario
//     const use = user.find(u => u.email === email && u.password === password);

//     // almacenar el id del usuario en la sesion
//     if (use) {
//         req.session.userId = use.id;
//         res.send('Login successful');
//     } else {
//         res.status(401).send('Invalid credentials');
//     }
// });


// // Ruta protegida 
// app.get('/protected', (req, res) => {
//     // verificar si hay una sesion activa
//     if (req.session.userId) {
//         res.send('Welcome, you are logged in');
//     } else {
//         res.status(401).send('You are not logged in');
//     }
// });

// // Ruta de sesion
// app.get('/logout', (req, res) => {
//     req.session.destroy(err => {
//         if (err) {
//             console.error(err);
//             res.status(500).send('Error logging out');
//         } else {
//             // Redireccionar a la página de inicio después de cerrar sesión
//             res.redirect('/'); // Redirect to the home page after logout

//         }
//     });    

// });

// app.listen(3005, () =>{
//     console.log('Servidor escuchando en el puerto 3005');
// });

const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const db = require('./conexionDB/db');

const app = express();
app.use(express.json());

// Configuracion del middleware de sesion
app.use(session({
    secret: 'kerberos',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false,
        maxAge: 300000 // 5 minutos en milisegundo
    }
}));

// Ruta para obtener usuarios
app.get('/users', async (req, res) => {
  if (req.session.userId) {
    try {
      const result = await db.query('SELECT * FROM register');
      res.status(200).json(result.rows);
    } catch (error) {
      console.error(error); // Agregar log de error para depuración
      res.status(500).json({ message: 'Server error' });
    }
  } else {
    return res.status(401).json({message: 'Usuario no autorizado'});
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

// Ruta de inicio de sesion
app.post('/login', async(req, res) => {
    const { email, password } = req.body;

    // validar que se completen todos los campos
    if (!email || !password) {
        return res.status(400).json({message: 'Todos los campos deben estar completos'});
    }

    try{
        // Buscar usuario por email
        const result = await db.query('SELECT * FROM register WHERE email = $1', [email]);
        if(result.rows.length === 0){
            return res.status(401).json({ message: 'Credenciales inválidas'});
        }

        // Si el email existe guardar usuario en user
        const user = result.rows[0];

        // Comparar contraseñas
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciales inválidas'});
        }

        // Almacenar el ID del usuario en la sesion
        req.session.userId = user.id;
        res.status(200).json({message: 'Inicio de sesión exitoso'});
    } catch (error){
        console.error(error); // Agregar log de error para depuración
        res.status(500).json({ message: 'Server error' });
    }
});

// Ruta protegida 
app.get('/protected', (req, res) => {
    if (req.session.userId) {
        res.status(200).json({ message: 'Bienvenido a la ruta protegida'});
    } else {
        res.status(401).json({ message: 'No autorizado' });
    }
});

// Ruta de cierre de sesion
app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error(err); // Agregar log de error para depuración
            res.status(500).json({ message: 'Server error' });
        } else {
            res.status(200).json({ message: 'Sesión cerrada exitosamente'});
        }
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});