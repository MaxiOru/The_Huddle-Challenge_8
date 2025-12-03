// ============================================================================
// MIDDLEWARE DE RATE LIMITING
// ============================================================================

const rateLimiter = require('express-rate-limit');

// Limita intentos de login: 5 intentos por IP cada 15 minutos
const loginLimiter = rateLimiter({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: { message: 'Demasiados intentos de inicio de sesión. Intente de nuevo en 15 minutos.' },
    standardHeaders: true,
    legacyHeaders: false,
});

module.exports = {
    loginLimiter
};
