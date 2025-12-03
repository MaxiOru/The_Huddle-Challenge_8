// ============================================================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================================================

const jwt = require('jsonwebtoken');
const User = require('../models/userModels');
const { JWT_SECRET } = require('../utils/jwt');

// Verifica autenticación mediante JWT o Session
// Intenta JWT primero (header Authorization), luego Session (cookie sid)
function auth(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    // Intenta con JWT
    if (token) {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            const user = User.findById(decoded.id);
            if (!user) {
                return res.status(401).json({ message: 'Usuario no encontrado' });
            }
            req.user = { id: user.id, email: user.email, role: user.role };
            return next();
        } catch (err) {
            return res.status(403).json({ message: 'Token inválido o expirado' });
        }
    }

    // Si no hay token, intenta con Session
    const Session = require('../models/sessionModel');
    const sessionId = req.cookies && req.cookies.sid;

    if (!sessionId) {
        return res.status(401).json({ message: 'No autenticado: token o sesión requerida' });
    }

    const session = Session.findById(sessionId);
    if (!session) {
        return res.status(401).json({ message: 'Sesión inválida' });
    }

    if (new Date(session.expires_at) < new Date()) {
        Session.delete(sessionId);
        return res.status(401).json({ message: 'Sesión expirada' });
    }

    const user = User.findById(session.user_id);
    if (!user) {
        return res.status(401).json({ message: 'Usuario no encontrado' });
    }

    req.user = { id: user.id, email: user.email, role: user.role };
    next();
}

module.exports = {
    auth
};
