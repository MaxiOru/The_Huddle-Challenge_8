// ============================================================================
// MIDDLEWARE DE VALIDACIÓN DE ENTRADA
// ============================================================================

const { body, validationResult } = require('express-validator');

// Validación simplificada para registro y login
const registerValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 }).trim().escape()
];

const loginValidation = [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty().trim().escape()
];

// Maneja errores de validación
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
