const db = require('../config/database');
const { hashPassword } = require('../utils/password');

const User = {
    create: (email, password, role='user') => {
        const hashed = hashPassword(password);
        const stmt = db.prepare(`INSERT INTO users (email, password, role) VALUES (?, ?, ?)`);
        const info = stmt.run(email, hashed, role);
        return {  id: info.lastInsertRowid, email, role };
    },
    findByEmail: (email) => {
        const stmt = db.prepare (`Select * FROM users WHERE email = ?`);
        return stmt.get(email);
    },
    findById: (id) => {
        const stmt = db.prepare('Select * From users WHERE id = ?');
        return stmt.get(id)
    },
    findAll: () => {
        const stmt = db.prepare(`SELECT id, email, role FROM users`);
        return stmt.all()
    },
    deleteById: (id) => {
        const stmt = db.prepare('DELETE FROM users WHERE id=?');
        return stmt.run(id);
    }
};
module.exports = User;