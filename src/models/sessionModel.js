const db = require('../config/database');

const Session = {
    create: (sessionId, userId, data, expiresAt) => {
        const stmt = db.prepare('INSERT INTO sessions(id, user_id, data, expires_at) VALUES (?, ?, ?, ?)');
        return stmt.run(sessionId, userId, JSON.stringify(data), expiresAt);
    },
    findById: (sessionId) => {
        const stmt = db.prepare('SELECT id, user_id, data, expires_at FROM sessions WHERE id = ?');
        const row = stmt.get(sessionId);
        if (!row){
            return null;
        }
        try {
            row.data = JSON.parse(row.data);
        }catch (e) {
            row.data = {};
        }
        return row;
    },

    delete: (sessionId) => {
        const stmt = db.prepare('DELETE FROM sessions WHERE id = ?');
        return stmt.run(sessionId);
    },
    deleteByUserId: (userId) => {
        const stmt = db.prepare('DELETE FROM sessions WHERE user_id = ?');
        return stmt.run(userId);
    }

};

module.exports = Session;