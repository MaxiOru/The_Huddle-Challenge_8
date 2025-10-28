const jwt = require ('jsonwebtoken');
const bcrypt = require ('bcrypt');
const User = require ('../models/useModel');

const SECRET = process.env.JWT_SECRET || 'clave_secrete';

const authController = {
    register: (req, res) => {
        const { username, password } = req.body;

        if (!username || !password){
            return res.status(404).json({ message: 'Usuarios y/o contraseñña requeridos.' });
        };

        const existingUser = User.findByUsername(username);
        if (existingUser){
            return res.status(409).json({ message: 'El usuario ya existe.' });
        };

        User.create(username, password);
        res.status(201).json({ message: 'usuario registrado correctamente.' });
    },

    login: (req,res) => {
        const { username, password } = req.body;

        const user = User.findByUsername(username);
        if(!user){
            return res.status(401).json({ message: 'Credenciales invalidas' });
        };

        const valid = bcrypt.compareSync(password, user.password);
        if (!valid){
            return res.status(401).json({ message: 'Credenciales invalidas' })
        }
        
        const token= jwt.sign(
            {id: user.id,
            username: user.username,
            role: user.role
            }, 
            SECRET,
            { expiresIn: '1h' }
        );

        res.json({ message: 'Login exitoso', token })
    }
};

module.exports = authController;
