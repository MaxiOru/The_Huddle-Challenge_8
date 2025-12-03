# 📋 Cumplimiento de Requisitos de Seguridad - PassPort API

## Tabla de Cumplimiento

| # | Requisito | Estado | Archivo(s) | Código Específico |
|---|-----------|--------|------------|-------------------|
| **1** | **Hashing de contraseñas con bcrypt** | ✅ Implementado | `src/utils/password.js`<br>`src/models/userModels.js` | `hashPassword()` con bcrypt<br>`User.create()` usa hashing |
| **2** | **Sesiones con cookies (ID de sesión)** | ✅ Implementado | `src/models/sessionModel.js`<br>`src/controllers/authController.js` | `Session.create(sessionId, ...)`<br>`res.cookie('sid', sessionId)` |
| **3** | **JWT (generación y validación)** | ✅ Implementado | `src/utils/jwt.js`<br>`src/middleware/auth.js` | `generateToken()`<br>`verifyToken()`<br>`jwt.verify()` en auth |
| **4** | **RBAC - Roles (User/Admin)** | ✅ Implementado | `src/middleware/authorization.js`<br>`src/controllers/adminController.js` | `authorizeRoles('admin')`<br>Rutas `/admin/*` protegidas |
| **5** | **Cifrado en tokens y hash** | ✅ Implementado | `src/utils/jwt.js`<br>`src/utils/password.js` | JWT firmado con `JWT_SECRET`<br>bcrypt con `SALT_ROUNDS` |
| **6** | **Sanitización de entradas (XSS)** | ✅ Implementado | `src/middleware/validation.js` | `body().trim().escape()`<br>`normalizeEmail()` |
| **7** | **Tokens CSRF** | ✅ Implementado | `src/config/csrf.js`<br>`src/controllers/authController.js` | `csrfProtection` en rutas POST<br>`/csrf-token` endpoint |
| **8** | **Rate Limiting (intentos login)** | ✅ Implementado | `src/middleware/rateLimiter.js`<br>`src/server.js` | `loginLimiter` (5 intentos/15min)<br>Aplicado en `/auth/login` |
| **9** | **Cookies HTTP-only y Secure** | ✅ Implementado | `src/config/csrf.js`<br>`src/controllers/authController.js` | `httpOnly: true`<br>`secure: NODE_ENV === 'production'` |

---

## 📂 Desglose Detallado por Requisito

### 1️⃣ Hashing de contraseñas con bcrypt

**Requisito:** Almacena las contraseñas de forma segura usando un algoritmo de hashing (por ejemplo, bcrypt) para convertir las contraseñas en un código único e irreversible.

**Implementación:**

```javascript
// src/utils/password.js
const bcrypt = require('bcrypt');
const SALT_ROUNDS = parseInt(process.env.BCRYPT_ROUNDS) || 10;

function hashPassword(plainPassword) {
    return bcrypt.hashSync(plainPassword, SALT_ROUNDS);
}

function comparePassword(plainPassword, hash) {
    return bcrypt.compareSync(plainPassword, hash);
}
```

```javascript
// src/models/userModels.js
create: (email, password, role='user') => {
    const hashed = hashPassword(password);
    const stmt = db.prepare(`INSERT INTO users (email, password, role) VALUES (?, ?, ?)`);
    const info = stmt.run(email, hashed, role);
    return { id: info.lastInsertRowid, email, role };
}
```

**Ubicación:** `src/utils/password.js` (líneas 9-15), `src/models/userModels.js` (línea 5)

---

### 2️⃣ Sesiones con cookies (ID de sesión)

**Requisito:** Implementa la creación, mantenimiento y eliminación de sesiones con cookies. La cookie debe almacenar un identificador de sesión.

**Implementación:**

```javascript
// src/models/sessionModel.js
const Session = {
    create: (sessionId, userId, data, expiresAt) => {
        const stmt = db.prepare('INSERT INTO sessions(id, user_id, data, expires_at) VALUES (?, ?, ?, ?)');
        return stmt.run(sessionId, userId, JSON.stringify(data), expiresAt);
    },
    findById: (sessionId) => { /* ... */ },
    delete: (sessionId) => { /* ... */ },
    deleteByUserId: (userId) => { /* ... */ }
};
```

```javascript
// src/controllers/authController.js (líneas 68-82)
if (type === 'session') {
    const sessionId = generateSessionId();
    const expiresMs = 1000 * 60 * 60 * 24 * 7; // 7 días
    const expiresAt = new Date(Date.now() + expiresMs).toISOString();
    Session.create(sessionId, user.id, { email: user.email }, expiresAt);

    res.cookie('sid', sessionId, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: expiresMs
    });
}
```

**Ubicación:** `src/models/sessionModel.js`, `src/controllers/authController.js` (líneas 68-82, 99-107)

---

### 3️⃣ JWT (generación y validación)

**Requisito:** Implementa la autenticación basada en JWT, generando y validando tokens que contengan la información del usuario.

**Implementación:**

```javascript
// src/utils/jwt.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret';
const JWT_EXPIRATION = process.env.JWT_EXP || '1h';

function generateToken(payload, expiresIn = JWT_EXPIRATION) {
    return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verifyToken(token) {
    return jwt.verify(token, JWT_SECRET);
}
```

```javascript
// src/middleware/auth.js (líneas 14-27)
if (token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user = User.findById(decoded.id);
        if (!user) {
            return res.status(401).json({ message: 'Usuario no encontrado' });
        }
        req.user = { id: user.id, email: user.email, role: user.role };
        return next();
    } catch (err) {
        return res.status(403).json({ message: 'Token inválido o expirado' });
    }
}
```

```javascript
// src/controllers/authController.js (líneas 87-94)
const token = generateToken({
    id: user.id,
    email: user.email,
    role: user.role
});

res.json({ message: 'Login exitoso (jwt)', token });
```

**Ubicación:** `src/utils/jwt.js`, `src/middleware/auth.js` (líneas 14-27), `src/controllers/authController.js` (líneas 87-94)

---

### 4️⃣ RBAC - Roles (Usuario/Administrador)

**Requisito:** Define al menos dos roles: Usuario y Administrador. Implementa la lógica para restringir el acceso a ciertas rutas y funcionalidades basadas en el rol del usuario.

**Implementación:**

```javascript
// src/middleware/authorization.js
function authorizeRoles(...allowedRoles) {
    return (req, res, next) => {
        if (!req.user || !allowedRoles.includes(req.user.role)) {
            return res.status(403).json({ message: 'Acceso denegado: permisos insuficientes' });
        }
        next();
    };
}
```

```javascript
// src/controllers/adminController.js
// Listar todos los usuarios (solo admin)
router.get('/users', auth, authorizeRoles('admin'), (req, res) => {
    const users = User.findAll();
    res.json(users);
});

// Eliminar usuario por ID (solo admin + CSRF)
router.delete('/users/:id', csrfProtection, auth, authorizeRoles('admin'), (req, res) => {
    const id = parseInt(req.params.id, 10);
    User.deleteById(id);
    Session.deleteByUserId(id);
    res.json({ message: 'Usuario eliminado' });
});
```

**Ubicación:** `src/middleware/authorization.js`, `src/controllers/adminController.js` (líneas 10, 16)

---

### 5️⃣ Cifrado en tokens y hash

**Requisito:** Usa algoritmos de cifrado para proteger datos sensibles en los tokens y hash para contraseñas.

**Implementación:**

```javascript
// JWT - Cifrado simétrico con HS256
// src/utils/jwt.js
jwt.sign(payload, JWT_SECRET, { expiresIn }); // ← Firmado con HMAC SHA256

// Bcrypt - Hash unidireccional
// src/utils/password.js
bcrypt.hashSync(plainPassword, SALT_ROUNDS); // ← Hash con salt
```

**Variables de entorno:**
```env
JWT_SECRET=mi_super_secreto_para_jwt_2025_passportinc
BCRYPT_ROUNDS=10
```

**Ubicación:** `src/utils/jwt.js` (línea 11), `src/utils/password.js` (línea 10), `.env` (líneas 6, 10)

---

### 6️⃣ Sanitización de entradas (XSS)

**Requisito:** Filtra y escapa las entradas del usuario para prevenir la ejecución de scripts maliciosos.

**Implementación:**

```javascript
// src/middleware/validation.js
const { body, validationResult } = require('express-validator');

const registerValidation = [
    body('email').isEmail().withMessage('Correo electrónico inválido').normalizeEmail(),
    body('password').isLength({ min: 6 }).withMessage('La contraseña debe tener al menos 6 caracteres').trim().escape(),
    body('username').optional().isAlphanumeric().withMessage('El nombre de usuario solo puede contener letras y números').trim().escape(),
    body('role').optional().isIn(['user', 'admin']).withMessage('El rol debe ser "user" o "admin"').trim(),
];

const loginValidation = [
    body('email').isEmail().withMessage('Correo electrónico inválido').normalizeEmail(),
    body('password').notEmpty().withMessage('La contraseña es obligatoria').trim().escape(),
];

function handleValidationErrors(req, res, next) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    next();
}
```

**Métodos de sanitización:**
- `.trim()` - Elimina espacios en blanco
- `.escape()` - Escapa caracteres HTML (`<`, `>`, `&`, `"`, `'`)
- `.normalizeEmail()` - Normaliza emails
- `.isAlphanumeric()` - Solo permite letras y números

**Ubicación:** `src/middleware/validation.js` (líneas 8-19)

---

### 7️⃣ Tokens CSRF

**Requisito:** Usa tokens CSRF para validar las solicitudes que cambian el estado.

**Implementación:**

```javascript
// src/config/csrf.js
const csurf = require('csurf');

const csrfProtection = csurf({ 
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax'
    }
});

module.exports = csrfProtection;
```

```javascript
// src/controllers/authController.js
// Obtener token CSRF
router.get('/csrf-token', csrfProtection, (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Todas las rutas POST protegidas con CSRF
router.post('/register', csrfProtection, registerValidation, handleValidationErrors, ...);
router.post('/login', csrfProtection, loginValidation, handleValidationErrors, ...);
router.post('/logout', csrfProtection, ...);
```

**Endpoints protegidos:**
- ✅ `POST /auth/register`
- ✅ `POST /auth/login`
- ✅ `POST /auth/logout`
- ✅ `DELETE /admin/users/:id`

**Ubicación:** `src/config/csrf.js`, `src/controllers/authController.js` (líneas 18, 23, 45, 99), `src/controllers/adminController.js` (línea 16)

---

### 8️⃣ Rate Limiting (intentos de login)

**Requisito:** Implementa limitación de intentos de inicio de sesión, como bloqueos temporales después de múltiples intentos fallidos.

**Implementación:**

```javascript
// src/middleware/rateLimiter.js
const rateLimiter = require('express-rate-limit');

const loginLimiter = rateLimiter({
    windowMs: 15 * 60 * 1000,  // 15 minutos
    max: 5,                     // Máximo 5 intentos
    message: { 
        message: 'Demasiados intentos de inicio de sesión. Intente de nuevo en 15 minutos.' 
    },
    standardHeaders: true,
    legacyHeaders: false,
});

module.exports = { loginLimiter };
```

```javascript
// src/server.js (línea 51)
app.use('/auth/login', loginLimiter);
app.use('/auth', createAuthRouter(csrfProtection));
```

**Configuración:**
- **Ventana de tiempo:** 15 minutos
- **Máximo de intentos:** 5 por IP
- **Mensaje:** "Demasiados intentos de inicio de sesión. Intente de nuevo en 15 minutos."

**Ubicación:** `src/middleware/rateLimiter.js`, `src/server.js` (línea 51)

---

### 9️⃣ Cookies HTTP-only y Secure

**Requisito:** Configura las flags HTTP-only y Secure en las cookies.

**Implementación:**

```javascript
// src/config/csrf.js (Cookie de CSRF)
const csrfProtection = csurf({ 
    cookie: {
        httpOnly: true,  // ✅ No accesible desde JavaScript
        secure: process.env.NODE_ENV === 'production',  // ✅ Solo HTTPS en producción
        sameSite: 'lax'  // ✅ Protección adicional CSRF
    }
});
```

```javascript
// src/controllers/authController.js (Cookie de sesión)
res.cookie('sid', sessionId, {
    httpOnly: true,  // ✅ No accesible desde JavaScript
    secure: process.env.NODE_ENV === 'production',  // ✅ Solo HTTPS en producción
    sameSite: 'lax',  // ✅ Protección adicional CSRF
    maxAge: expiresMs  // 7 días
});
```

**Flags configuradas:**
- ✅ **httpOnly: true** - Previene acceso desde JavaScript (XSS)
- ✅ **secure: true (en producción)** - Solo se envía por HTTPS
- ✅ **sameSite: 'lax'** - Protección adicional contra CSRF

**Ubicación:** `src/config/csrf.js` (líneas 9-11), `src/controllers/authController.js` (líneas 73-77)

---

## ✅ Resumen General

### Estado de Implementación: **100% Completo**

Todos los **9 requisitos de seguridad** han sido implementados correctamente en el sistema PassPort-API:

| Categoría | Implementado | Total |
|-----------|--------------|-------|
| Autenticación y Autorización | ✅ 4/4 | 100% |
| Cifrado y Hashing | ✅ 2/2 | 100% |
| Protección contra Ataques | ✅ 3/3 | 100% |

### Tecnologías Utilizadas

- **bcrypt** - Hashing de contraseñas
- **jsonwebtoken** - Autenticación JWT
- **csurf** - Protección CSRF
- **express-validator** - Validación y sanitización
- **express-rate-limit** - Limitación de peticiones
- **better-sqlite3** - Base de datos
- **helmet** - Seguridad adicional HTTP headers
- **cookie-parser** - Manejo de cookies

### Arquitectura Modular

```
src/
├── config/          ← Configuraciones (DB, CSRF)
├── controllers/     ← Lógica de rutas
├── middleware/      ← Seguridad y validación
├── models/          ← Acceso a datos
└── utils/           ← Funciones auxiliares
```

---

**Documento generado:** Noviembre 20, 2025  
**Proyecto:** PassPort Inc. - Sistema de Autenticación  
**Versión:** 1.0.0
