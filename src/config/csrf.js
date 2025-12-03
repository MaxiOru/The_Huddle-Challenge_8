// ============================================================================
// CONFIGURACIÓN DE CSRF PROTECTION
// ============================================================================

const csurf = require('csurf');

// Middleware de protección CSRF configurado con cookies
const csrfProtection = csurf({ 
    cookie: {
        httpOnly: true,
        secure: false,
        sameSite: 'lax'
    }
});

module.exports = csrfProtection;
