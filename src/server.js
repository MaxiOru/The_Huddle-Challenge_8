const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const { loginLimiter } = require('./middleware/rateLimiter');
const csrfProtection = require('./config/csrf');
const createAuthRouter = require('./controllers/authController');
const createAdminRouter = require('./controllers/adminController');

const app = express();

// Middleware globales
app.use(helmet());
app.use(cookieParser());
app.use(express.json());

// Ruta raíz
app.get('/', (req, res) => {
    res.json({
        message: 'PassPort Inc. - API de Autenticación',
        endpoints: {
            auth: {
                csrf: 'GET /auth/csrf-token',
                register: 'POST /auth/register',
                login: 'POST /auth/login',
                logout: 'POST /auth/logout'
            },
            admin: {
                listUsers: 'GET /admin/users (requiere token admin)',
                deleteUser: 'DELETE /admin/users/:id (requiere token admin)'
            }
        }
    });
});

// Routers
app.use('/auth/login', loginLimiter);
app.use('/auth', createAuthRouter(csrfProtection));
app.use('/admin', createAdminRouter(csrfProtection));

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`Servidor en http://localhost:${PORT}`);
});