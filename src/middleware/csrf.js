const csrf = require('csurf');

// configuracion del middleware CSRF
const csrfProtection = csrf({
    cookie: {
        httpOnly: true, // evita acceso desde JS del lado del cliente
        secure: true,   // solo se envia por HTTPS
        sameSite: 'strict'
    }
});

module.exports = csrfProtection;