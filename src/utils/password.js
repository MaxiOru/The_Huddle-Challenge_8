// ============================================================================
// UTILIDADES DE PASSWORD (HASHING)
// ============================================================================

const bcrypt = require('bcrypt');

const SALT_ROUNDS = 10;

// Hashea contraseña con bcrypt
function hashPassword(plainPassword) {
    return bcrypt.hashSync(plainPassword, SALT_ROUNDS);
}

// Compara contraseña plana con hash
function comparePassword(plainPassword, hash) {
    return bcrypt.compareSync(plainPassword, hash);
}

module.exports = { hashPassword, comparePassword };
