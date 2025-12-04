const { body, validationResult } = require('express-validator');

// ARRAY de reglas de validación para registro
// Se ejecuta cada regla en orden sobre req.body
// No retorna error inmediatamente, solo marca los errores encontrados
const registerValidation = [
    body('email').isEmail().normalizeEmail(),        // Valida email y normaliza formato
    body('password').isLength({ min: 6 }).trim().escape()  // Min 6 caracteres, limpia espacios y escapa HTML
];

// ARRAY de reglas de validación para login
const loginValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty().trim().escape()      // Solo verifica que no esté vacío
];

// FUNCIÓN que revisa si las validaciones anteriores encontraron errores
// Se ejecuta DESPUÉS de registerValidation/loginValidation en la cadena de middlewares
// Si hay errores: retorna 400 con detalles
// Si no hay errores: llama next() para continuar al controlador
function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
}

module.exports = {
    registerValidation,
    loginValidation,
    handleValidationErrors
};
