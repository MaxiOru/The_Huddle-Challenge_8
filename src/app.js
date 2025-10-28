// configuracion principal de express
const express = require('express');
const cookieParser = require ('cookie-perser');
const helmet = require ('helmet')
const rateLimit = require('express-rate.limit');

//rutas de roles
const authRoutes = require('./routes/authRoutes');
const adminRoutes = require('./routes/adminRoutes');

const app = express();

//Middleware globales
app.use(helmet()); //cabeceras de seguridad (HTTP)
app.use(express.json()); //parsear JSON
app.use(cookieParser()); // Parsear cookies

//limitar intentos de login (proteccion fuerza bruta)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message:'Demasiados intentos, intenta mas tarde.'
});

app.use('./api/auth/login', limiter);

//rutas de autenticacion
app.use('/api/auth', authRoutes);

//rutas de admiistracion (protegidas)
app.use('/api/admin', adminRoutes);

module.exports= app