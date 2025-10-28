const rateLimiter = require('express-rate-limit');

const loginLimiter = rateLimiter({
    windowMs: 15*60*1000, //  minutos
    max: 5,
    message: { message: 'Demasiados intentos de inicio de sesion. Intente de nuevo mas tarde.'},
    standarHeaders: true,
    legacyHeaders: false,
});

module.exports = loginLimiter;