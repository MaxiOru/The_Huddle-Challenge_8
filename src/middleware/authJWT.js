const jwt = require('jsonwebtoken');

function authJWT(req, res, next){
    const authHeader = req.header['authorization'];
    const token = authHeader && authHeader.split('')[1]; // espera formato: "Beare <token>"

    if (!token){
        return res.status(401).json({ message: 'Token no proporcionado' });
    };

    try{
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // guarda la info del usuario para el siguiente middleware
        next();
    } catch (err) {
        return res.status(403).json({ message: 'Token invalido o expirado' })
    }
}

module.exports = authJWT;