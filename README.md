# 🛡️ PassPort-API - Sistema de Autenticación y Autorización

API REST segura que implementa autenticación dual (JWT y Sessions), control de acceso basado en roles (RBAC) y múltiples capas de seguridad.

## 🚀 Características principales

- ✅ **Autenticación dual**: JWT (stateless) y Sessions (stateful)
- ✅ **RBAC**: Control de acceso por roles (User/Admin)
- ✅ **Seguridad multicapa**: CSRF, Rate Limiting, Helmet, bcrypt
- ✅ **Validación robusta**: Sanitización y validación de entradas
- ✅ **Cookies seguras**: HttpOnly, Secure, SameSite
- ✅ **Base de datos SQLite**: Persistencia simple y portátil
- ✅ **Verificación de tokens**: Endpoint para validar JWT

## 📋 Requisitos

- Node.js v14+
- npm v6+

## 🔧 Instalación

```bash
# Clonar repositorio
git clone https://github.com/MaxiOru/The_Huddle-Challenge_8.git
cd The_Huddle-Challenge_8

# Instalar dependencias
npm install

# Iniciar servidor
npm start
```

El servidor estará disponible en `http://localhost:3000`

El servidor estará disponible en: `http://localhost:3000`

## 📡 Endpoints de la API

### Autenticación

#### Obtener token CSRF
```http
GET /auth/csrf-token
```

**Respuesta:**
```json
{
  "csrfToken": "abc123xyz..."
}
```

### 2. Registrar usuario
```bash
POST http://localhost:3000/auth/register
Headers:
  X-CSRF-Token: abc123xyz...
Body:
{
  "email": "user@test.com",
  "password": "password123",
  "role": "user"
}
```

### 3. Login con JWT
```bash
POST http://localhost:3000/auth/login
Headers:
  X-CSRF-Token: abc123xyz...
Body:
{
  "email": "user@test.com",
  "password": "password123",
  "type": "jwt"
}
```

**Respuesta:**
```json
{
  "message": "Login exitoso (jwt)",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### 4. Login con Session
```bash
POST http://localhost:3000/auth/login
Headers:
  X-CSRF-Token: abc123xyz...
Body:
{
  "email": "user@test.com",
  "password": "password123",
  "type": "session"
}
```

**Respuesta:**
```json
{
  "message": "Login exitoso (session)",
  "user": {
    "id": 1,
    "email": "user@test.com",
    "role": "user"
  }
}
```
*Cookie sid enviada automáticamente*

### 5. Verificar token JWT
```bash
POST http://localhost:3000/auth/verify-token
Body:
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Respuesta válida:**
```json
{
  "message": "Token válido"
}
```

**Respuesta inválida:**
```json
{
  "message": "Token inválido o expirado"
}
```

### 6. Acceder a ruta de admin (con JWT)
```bash
GET http://localhost:3000/admin/users
Headers:
  Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    "role": "admin"
  },
  {
    "id": 2,
    "email": "user@example.com",
    "role": "user"
  }
]
```

### 7. Acceder a ruta de admin (con Session)
```bash
GET http://localhost:3000/admin/users
Cookie: sid=abc123...
```

### 8. Logout
```bash
POST http://localhost:3000/auth/logout
Headers:
  X-CSRF-Token: abc123xyz...
  Authorization: Bearer <token>  (o Cookie: sid=<sessionId>)
```

## 🏗️ Arquitectura

```
src/
├── config/
│   ├── csrf.js           # Configuración CSRF
│   └── database.js       # Configuración SQLite
├── controllers/
│   ├── adminController.js  # Endpoints de administración
│   └── authController.js   # Endpoints de autenticación
├── middleware/
│   ├── auth.js            # Middleware de autenticación (JWT/Session)
│   ├── authorization.js   # Middleware RBAC
│   ├── rateLimiter.js     # Limitación de peticiones
│   └── validation.js      # Validación y sanitización
├── models/
│   ├── sessionModel.js    # Modelo de sesiones
│   └── userModels.js      # Modelo de usuarios
├── utils/
│   ├── jwt.js             # Utilidades JWT
│   └── password.js        # Utilidades de hash
└── server.js              # Punto de entrada
```

## 🔐 Medidas de seguridad implementadas

### 1. **Hashing de contraseñas (bcrypt)**
- Algoritmo: bcrypt con 10 salt rounds
- Contraseñas nunca almacenadas en texto plano

### 2. **Autenticación dual**
- **JWT**: Tokens firmados con HS256, expiración 1h
- **Sessions**: IDs aleatorios, expiración 7 días

### 3. **RBAC (Role-Based Access Control)**
- Roles: `user`, `admin`
- Middleware `authorizeRoles()` restringe acceso

### 4. **Protección CSRF**
- Tokens únicos por sesión
- Validación en rutas POST/DELETE

### 5. **Rate Limiting**
- Login: 5 intentos cada 15 minutos
- Previene ataques de fuerza bruta

### 6. **Cookies seguras**
- `httpOnly: true` (previene XSS)
- `secure: false` (desarrollo local)
- `sameSite: 'strict'` (previene CSRF)

### 7. **Validación y sanitización**
- express-validator en todas las entradas
- Escape de caracteres especiales
- Normalización de emails

### 8. **Helmet.js**
- Headers de seguridad HTTP automáticos
- Protección contra clickjacking, XSS, etc.

## 📦 Dependencias

```json
{
  "bcrypt": "^6.0.0",
  "better-sqlite3": "^12.4.1",
  "cookie-parser": "^1.4.7",
  "csurf": "^1.11.0",
  "express": "^5.1.0",
  "express-rate-limit": "^8.1.0",
  "express-validator": "^7.3.0",
  "helmet": "^8.1.0",
  "jsonwebtoken": "^9.0.2"
}
```

## 📝 Notas de desarrollo

- **Puerto**: 3000 (hardcodeado)
- **JWT Secret**: Hardcodeado en `src/utils/jwt.js`
- **Expiración JWT**: 1 hora
- **Expiración Session**: 7 días
- **Salt rounds**: 10
   - GET `http://localhost:3000/auth/csrf-token`
## 🗄️ Base de datos

### Tabla: `users`
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user'
);
```

### Tabla: `sessions`
```sql
CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    data TEXT,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## 🔄 Flujo de autenticación

### JWT Flow:
```
1. Cliente → POST /auth/login (type: "jwt")
2. API valida credenciales
3. API genera token JWT
4. Cliente recibe token
5. Cliente envía token en header Authorization: Bearer <token>
6. Middleware auth verifica token con jwt.verify()
```

### Session Flow:
```
1. Cliente → POST /auth/login (type: "session")
2. API valida credenciales
3. API genera sessionId y lo guarda en BD
4. API envía cookie sid=<sessionId>
5. Navegador envía cookie automáticamente
6. Middleware auth busca session en BD
```

## 📄 Licencia

MIT

## 👨‍💻 Autor

Proyecto desarrollado como parte de The Huddle - Reto 8
