// ============================================================================
// UTILIDADES JWT
// ============================================================================

const jwt = require('jsonwebtoken');

const JWT_SECRET = 'jwt_secreto_challenge_8';
const JWT_EXPIRATION = '1h';

// Genera token JWT firmado con payload y tiempo de expiración
function generateToken(payload, expiresIn = JWT_EXPIRATION) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

// Verifica y decodifica token JWT
function verifyToken(token) {
    return jwt.verify(token, JWT_SECRET);
}

module.exports = { generateToken, verifyToken, JWT_SECRET };
