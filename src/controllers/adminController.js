const express = require('express');
const User = require('../models/userModels');
const Session = require('../models/sessionModel');
const { auth } = require('../middleware/auth');
const { authorizeRoles } = require('../middleware/authorization');

const router = express.Router();

// Configurar rutas de administración
function createAdminRouter(csrfProtection) {
    // Listar todos los usuarios (solo admin)
    router.get('/users', auth, authorizeRoles('admin'), (req, res) => {
        const users = User.findAll();
        res.json(users);
    });
    
    // Eliminar usuario por ID (solo admin + CSRF)
    router.delete('/users/:id', csrfProtection, auth, authorizeRoles('admin'), (req, res) => {
        const id = parseInt(req.params.id, 10);
        if (!id) {
            return res.status(400).json({ message: 'Id invalido' });
        }
        
        User.deleteById(id);
        // Borrar sesiones del usuario eliminado
        Session.deleteByUserId(id);
        
        res.json({ message: 'Usuario eliminado' });
    });

    return router;
}

module.exports = createAdminRouter;