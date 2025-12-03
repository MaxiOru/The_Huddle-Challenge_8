# PassPort Inc. - Sistema de Autenticación

Sistema de autenticación robusto y seguro con soporte para JWT y sesiones persistentes, implementando las mejores prácticas de seguridad web.

## 🚀 Características

- ✅ **Registro y Login** con email y contraseña
- ✅ **Autenticación JWT** (stateless)
- ✅ **Sesiones persistentes** con cookies seguras (stateful)
- ✅ **Protección CSRF** para operaciones críticas
- ✅ **Rate Limiting** contra ataques de fuerza bruta
- ✅ **Control de acceso basado en roles** (RBAC)
- ✅ **Validación y sanitización** de datos de entrada
- ✅ **Logging de auditoría** de intentos de autenticación
- ✅ **Encriptación de contraseñas** con bcrypt
- ✅ **Headers de seguridad** con Helmet

## 📋 Requisitos

- Node.js 16+
- npm o yarn

## 🔧 Instalación

```bash
# Clonar el repositorio
git clone https://github.com/MaxiOru/The_Huddle-Challenge_8.git
cd The_Huddle-Challenge_8

# Instalar dependencias
npm install

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores

# Iniciar servidor
npm start
```

## 🌐 Uso

### Iniciar el servidor

```bash
# Modo producción
npm start

# Modo desarrollo (con auto-reload)
npm run dev
```

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
  "csrfToken": "token-generado"
}
```

#### Registrar usuario
```http
POST /auth/register
Content-Type: application/json
X-CSRF-Token: token-csrf

{
  "email": "usuario@example.com",
  "password": "contraseña123",
  "username": "nombreusuario"
}
```

**Respuesta exitosa:**
```json
{
  "message": "Usuario registrado correctamente",
  "user": {
    "id": 1,
    "email": "usuario@example.com"
  }
}
```

#### Login con JWT
```http
POST /auth/login
Content-Type: application/json
X-CSRF-Token: token-csrf

{
  "email": "usuario@example.com",
  "password": "contraseña123",
  "type": "jwt"
}
```

**Respuesta exitosa:**
```json
{
  "message": "Login exitoso (jwt)",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Login con Sesión
```http
POST /auth/login
Content-Type: application/json
X-CSRF-Token: token-csrf

{
  "email": "usuario@example.com",
  "password": "contraseña123",
  "type": "session"
}
```

**Respuesta exitosa:**
```json
{
  "message": "Login exitoso (session)",
  "user": {
    "id": 1,
    "email": "usuario@example.com",
    "role": "user"
  }
}
```

#### Logout
```http
POST /auth/logout
X-CSRF-Token: token-csrf
```

**Respuesta:**
```json
{
  "message": "Sesión cerrada"
}
```

### Administración (requiere rol admin)

#### Listar usuarios
```http
GET /admin/users
Authorization: Bearer <jwt-token>
```

**Respuesta:**
```json
[
  {
    "id": 1,
    "email": "admin@example.com",
    "role": "admin"
  },
  {
    "id": 2,
    "email": "user@example.com",
    "role": "user"
  }
]
```

#### Eliminar usuario
```http
DELETE /admin/users/:id
Authorization: Bearer <jwt-token>
X-CSRF-Token: token-csrf
```

**Respuesta:**
```json
{
  "message": "Usuario eliminado"
}
```

## 🏗️ Estructura del Proyecto

```
.
├── src/
│   ├── server.js              # Servidor principal con configuración
│   ├── middleware.js          # Todos los middlewares consolidados
│   ├── utils.js               # Utilidades (JWT, bcrypt, logger)
│   ├── config/
│   │   └── database.js        # Configuración de base de datos
│   ├── controllers/
│   │   ├── authController.js  # Controlador de autenticación
│   │   └── adminController.js # Controlador de administración
│   ├── models/
│   │   ├── userModels.js      # Modelo de usuarios
│   │   └── sessionModel.js    # Modelo de sesiones
│   ├── data/
│   │   └── database.db        # Base de datos SQLite
│   └── logs/
│       └── auth.log           # Logs de autenticación
├── .env                       # Variables de entorno
├── package.json               # Dependencias del proyecto
└── README.md                  # Este archivo
```

## 🔐 Seguridad

### Protecciones Implementadas

1. **CSRF Protection**: Tokens CSRF para operaciones POST/DELETE
2. **Rate Limiting**: 
   - Login: 5 intentos por 15 minutos
   - API general: 100 peticiones por 15 minutos
3. **Helmet**: Headers de seguridad HTTP
4. **bcrypt**: Hash de contraseñas con salt rounds
5. **JWT**: Tokens firmados con secreto
6. **Cookies seguras**: httpOnly, secure (producción), sameSite
7. **Validación de entrada**: express-validator
8. **RBAC**: Control de acceso basado en roles

### Variables de Entorno

Crea un archivo `.env` en la raíz del proyecto:

```env
# Servidor
PORT=3000
NODE_ENV=development

# JWT
JWT_SECRET=tu_secreto_jwt_super_seguro_cambialo_en_produccion
JWT_EXP=1h

# Bcrypt
BCRYPT_ROUNDS=10

# Base de datos
DB_PATH=./src/data/database.db

# Logs
LOGIN_LOG=./src/logs/auth.log
```

⚠️ **IMPORTANTE**: Cambia `JWT_SECRET` a un valor seguro en producción.

## 📦 Dependencias

```json
{
  "bcrypt": "^6.0.0",
  "better-sqlite3": "^12.4.1",
  "cookie-parser": "^1.4.7",
  "csurf": "^1.11.0",
  "dotenv": "^17.2.3",
  "express": "^5.1.0",
  "express-rate-limit": "^8.1.0",
  "express-validator": "^7.3.0",
  "helmet": "^8.1.0",
  "jsonwebtoken": "^9.0.2"
}
```

## 🧪 Pruebas con Postman

1. **Obtener token CSRF**
   - GET `http://localhost:3000/auth/csrf-token`
   - Guarda el `csrfToken` de la respuesta

2. **Registrar usuario**
   - POST `http://localhost:3000/auth/register`
   - Headers: `X-CSRF-Token: <token-csrf>`
   - Body: `{ "email": "test@test.com", "password": "123456" }`

3. **Login con JWT**
   - POST `http://localhost:3000/auth/login`
   - Headers: `X-CSRF-Token: <token-csrf>`
   - Body: `{ "email": "test@test.com", "password": "123456", "type": "jwt" }`
   - Guarda el `token` de la respuesta

4. **Acceder a rutas protegidas**
   - GET `http://localhost:3000/admin/users`
   - Headers: `Authorization: Bearer <jwt-token>`

## 🛠️ Desarrollo

### Comandos disponibles

```bash
# Iniciar servidor en modo producción
npm start

# Iniciar servidor en modo desarrollo (auto-reload)
npm run dev

# Ejecutar tests (cuando se implementen)
npm test
```

### Agregar nuevo middleware

Edita `src/middleware.js` y añade tu middleware al final del archivo:

```javascript
function miMiddleware(req, res, next) {
  // Tu lógica aquí
  next();
}

module.exports = {
  // ... otros middlewares
  miMiddleware,
};
```

### Agregar nueva utilidad

Edita `src/utils.js` y añade tu función:

```javascript
function miUtilidad(param) {
  // Tu lógica aquí
  return resultado;
}

module.exports = {
  // ... otras utilidades
  miUtilidad,
};
```

## 📝 Roles de Usuario

- **user**: Usuario estándar (por defecto)
- **admin**: Administrador con permisos completos

Para crear un administrador, modifica el rol directamente en la base de datos o implementa un endpoint de promoción.

## 🐛 Troubleshooting

### El servidor no inicia

- Verifica que el puerto 3000 no esté en uso
- Verifica que las dependencias estén instaladas: `npm install`
- Verifica que el archivo `.env` exista y tenga las variables correctas

### Error "Token inválido o expirado"

- El token JWT ha expirado (por defecto 1h)
- Solicita un nuevo token haciendo login nuevamente

### Error "Demasiados intentos de inicio de sesión"

- Has excedido el límite de 5 intentos en 15 minutos
- Espera 15 minutos o reinicia el servidor en desarrollo

### Base de datos corrupta

```bash
# Eliminar base de datos y dejar que se recree
rm src/data/database.db
npm start
```

## 📄 Licencia

ISC

## 👥 Autor

MaxiOru - [GitHub](https://github.com/MaxiOru)

## 🔗 Enlaces

- Repositorio: [The_Huddle-Challenge_8](https://github.com/MaxiOru/The_Huddle-Challenge_8)
- Issues: [Reportar problema](https://github.com/MaxiOru/The_Huddle-Challenge_8/issues)
