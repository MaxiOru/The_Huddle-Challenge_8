const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');

const db = new Database('./src/config/database.db');

db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE, 
    password TEXT,
    role TEXT DEFAULT 'user'
    )
    `).run();

const user = {
    create: (username, password) => {
        const hashed = bcrypt.hashSync(password, 10);
        const stmt = db.prepare(`INSERT INTO users (username, password) VALUES (?, ?)`);
        stmt.run(username, hashed);
    },
    findByUsername: (username) => {
        const stmt = db.prepare (`Select * FROM users WHERE username = ?`);
        return stmt.get(username);
    }
};
module.exports = User;