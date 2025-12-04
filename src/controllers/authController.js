const express = require('express');
const crypto = require('crypto');
const User = require('../models/userModels');
const Session = require('../models/sessionModel');
const { generateToken } = require('../utils/jwt');
const { comparePassword } = require('../utils/password');
const { verifyToken } = require('../utils/jwt');
const { auth } = require('../middleware/auth');
const { registerValidation, loginValidation, handleValidationErrors } = require('../middleware/validation');

const router = express.Router();

// Helper: generar ID de sesión
function generateSessionId() {
    return crypto.randomBytes(32).toString('hex');
}

// Configurar rutas de autenticación
function createAuthRouter(csrfProtection) {
    // Obtener token CSRF
    router.get('/csrf-token', csrfProtection, (req, res) => {
        res.json({ csrfToken: req.csrfToken() });
    });

    // Registrar usuario
    router.post('/register', csrfProtection, registerValidation, handleValidationErrors, (req, res) => {
        const { email, password, role = 'user' } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email y/o contraseña requeridos.' });
        }

        const existingUser = User.findByEmail(email);
        if (existingUser) {
            return res.status(409).json({ message: 'El usuario ya existe.' });
        }
        //aca se crea mi usuario y a la vez en la parte del modelo se hashea la contraseña
        const created = User.create(email, password, role);
        
        res.status(201).json({
            message: 'Usuario registrado correctamente.',
            user: { id: created.id, email: created.email, role: created.role }
        });
    });

    // Login de usuario (JWT o Session)
    router.post('/login', csrfProtection, loginValidation, handleValidationErrors, (req, res) => {
        const { email, password, type = 'jwt' } = req.body;

        if (!email || !password) {
            return res.status(400).json({ message: 'Email y/o contraseña requeridos.' });
        }

        const user = User.findByEmail(email);
        if (!user) {
            return res.status(401).json({ message: 'Credenciales invalidas' });
        }

        const valid = comparePassword(password, user.password);
        if (!valid) {
            return res.status(401).json({ message: 'Credenciales invalidas' });
        }

        

        // Login con sesión persistente (cookies)
        if (type === 'session') {
            const sessionId = generateSessionId();
            const expiresMs = 1000 * 60 * 60 * 24 * 7; // 7 días
            const expiresAt = new Date(Date.now() + expiresMs).toISOString();
            Session.create(sessionId, user.id, { email: user.email }, expiresAt);

            res.cookie('sid', sessionId, {
                httpOnly: true,
                secure: false, // en produccion usar true
                sameSite: 'lax',
                maxAge: expiresMs
            });

            return res.json({
                message: 'Login exitoso (session)',
                user: { id: user.id, email: user.email, role: user.role }
            });
        } else if (type === 'jwt') {
            // Login con JWT (sin estado)
            const token = generateToken({
                id: user.id,
                email: user.email,
                role: user.role
            });

            return res.json({ message: 'Login exitoso (jwt)', token });
        } else {
            // Tipo de autenticación inválido
            return res.status(400).json({ 
                message: 'Tipo de autenticación inválido. Use "session" o "jwt".' 
            });
        }
    });

    // Cerrar sesión (logout)
    router.post('/logout', csrfProtection, auth, (req, res) => {
        const sid = req.cookies && req.cookies.sid;
        if (sid) {
            Session.delete(sid);
            res.clearCookie('sid');
            return res.json({ message: 'Sesión cerrada con limpieza' });
        }
        res.json({ message: 'Sesión cerrada' });
    });

    // Verificar token JWT
    router.post('/verify-token', (req, res) => {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({ message: 'Token requerido' });
        }

        try {
            verifyToken(token);
            res.status(200).json({ message: 'Token válido' });
        } catch (error) {
            res.status(401).json({ message: 'Token inválido o expirado' });
        }
    });

    return router;
}

module.exports = createAuthRouter;
