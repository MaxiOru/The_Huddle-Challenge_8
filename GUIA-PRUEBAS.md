# Guía de Pruebas con Postman# 🧪 Guía de Pruebas - PassPort Inc. API



Esta guía te ayudará a probar todos los endpoints de la API usando Postman paso a paso.Esta guía te muestra cómo probar todas las funcionalidades del sistema de autenticación.



## 📋 Configuración Inicial---



### 1. Iniciar el Servidor## 📋 Tabla de Contenidos



```bash1. [Iniciar el Servidor](#1-iniciar-el-servidor)

cd "C:\Users\usuario\Desktop\Penguin_CodePro\The Huddle\Octavo reto"2. [Probar con Postman](#2-probar-con-postman)

npm start3. [Convertir Usuario en Admin](#3-convertir-usuario-en-admin)

```4. [Verificar Logs](#4-verificar-logs)

5. [Verificar Base de Datos](#5-verificar-base-de-datos)

Verifica que veas:6. [Pruebas Manuales con PowerShell](#6-pruebas-manuales-con-powershell)

```

🚀 Servidor corriendo en http://localhost:3000---

```

## 1. 🚀 Iniciar el Servidor

### 2. Configurar Postman

```powershell

- Abre Postman# En la terminal de VS Code

- Crea una nueva Collection llamada "PassPort Inc API"npm start

- URL base: `http://localhost:3000````



## 🧪 Tests por Flujo**Salida esperada:**

```

### Flujo Completo de Autenticación🔐 PassPort Inc. - Sistema de Autenticación

🗄️  Base de datos inicializada correctamente

#### 1️⃣ Obtener Token CSRF🚀 Servidor corriendo en http://localhost:3000

```

**Request:**

```---

Method: GET

URL: http://localhost:3000/auth/csrf-token## 2. 📬 Probar con Postman

Headers: (ninguno)

Body: (ninguno)### Importar la Colección

```

1. Abre **Postman** en VS Code (panel lateral izquierdo)

**Response Esperada:**2. Haz clic en **"Import"**

```json3. Selecciona: `PassPort-API.postman_collection.json`

{

  "csrfToken": "v7TxM-qJ3Rw8..."### Orden de Ejecución

}

```Ejecuta los requests **en este orden**:



**Acción:** #### ✅ **Request 1: Get CSRF Token**

- ✅ Copia el valor de `csrfToken````

- Lo usarás en las siguientes peticionesGET http://localhost:3000/auth/csrf-token

```

---- Guarda automáticamente el token CSRF

- Necesario para todos los POST/DELETE

#### 2️⃣ Registrar un Usuario

#### ✅ **Request 2: Register User**

**Request:**```

```POST http://localhost:3000/auth/register

Method: POSTBody: {

URL: http://localhost:3000/auth/register  "email": "user@passportinc.com",

  "password": "User123456"

Headers:}

  Content-Type: application/jsonHeaders: X-CSRF-Token: {{csrfToken}}

  X-CSRF-Token: <pega-el-token-csrf-aquí>```



Body (raw JSON):#### ✅ **Request 3: Register Admin User**

{```

  "email": "usuario@test.com",POST http://localhost:3000/auth/register

  "password": "password123",Body: {

  "username": "testuser"  "email": "admin@passportinc.com",

}  "password": "Admin123456"

```}

Headers: X-CSRF-Token: {{csrfToken}}

**Response Esperada (201 Created):**```

```json

{#### ✅ **Request 4: Login with JWT**

  "message": "Usuario registrado correctamente",```

  "user": {POST http://localhost:3000/auth/login

    "id": 1,Body: {

    "email": "usuario@test.com"  "email": "user@passportinc.com",

  }  "password": "User123456",

}  "type": "jwt"

```}

Headers: X-CSRF-Token: {{csrfToken}}

**Posibles Errores:**```

- Guarda automáticamente el JWT token

❌ **409 Conflict** - Usuario ya existe:

```json#### ✅ **Request 5: Login with Session**

{```

  "message": "El usuario ya existe."POST http://localhost:3000/auth/login

}Body: {

```  "email": "user@passportinc.com",

  "password": "User123456",

❌ **400 Bad Request** - Validación fallida:  "type": "session"

```json}

{Headers: X-CSRF-Token: {{csrfToken}}

  "errors": [```

    {- Establece cookie `sid` automáticamente

      "msg": "Correo electrónico inválido",

      "param": "email"#### ⛔ **Request 6: Try Access Admin (Should Fail)**

    }```

  ]GET http://localhost:3000/admin/users

}Headers: Authorization: Bearer {{jwtToken}}

``````

- **Debe fallar con 403** porque el usuario no es admin

❌ **403 Forbidden** - Token CSRF inválido:

```json#### ✅ **Request 7: Login Failed**

{```

  "message": "invalid csrf token"POST http://localhost:3000/auth/login

}Body: {

```  "email": "user@passportinc.com",

  "password": "WrongPassword123",

---  "type": "jwt"

}

#### 3️⃣ Login con JWT (Sin Estado)```

- Prueba el logging de intentos fallidos

**Request:**

```#### ✅ **Request 8: Logout**

Method: POST```

URL: http://localhost:3000/auth/loginPOST http://localhost:3000/auth/logout

Headers: X-CSRF-Token: {{csrfToken}}

Headers:```

  Content-Type: application/json

  X-CSRF-Token: <pega-el-token-csrf-aquí>---



Body (raw JSON):## 3. 👑 Convertir Usuario en Admin

{

  "email": "usuario@test.com",### Opción A: Usando el Script Node.js

  "password": "password123",

  "type": "jwt"```powershell

}# Ejecutar el script

```node make-admin.js

```

**Response Esperada (200 OK):**

```json**Salida esperada:**

{```

  "message": "Login exitoso (jwt)",✅ Usuario admin@passportinc.com ahora es ADMIN

  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJ1c3VhcmlvQHRlc3QuY29tIiwicm9sZSI6InVzZXIiLCJpYXQiOjE2OTk4ODg4ODh9.abc123..."📋 Usuario actualizado: { email: 'admin@passportinc.com', role: 'admin' }

}```

```

### Opción B: Script PowerShell Manual

**Acción:**

- ✅ Copia el valor de `token````powershell

- Lo usarás para acceder a rutas protegidas# Convertir usuario en admin usando sqlite3

$db = ".\src\data\database.db"

**Posibles Errores:**$email = "admin@passportinc.com"



❌ **401 Unauthorized** - Credenciales incorrectas:# Usando better-sqlite3 desde Node

```jsonnode -e "const db = require('better-sqlite3')('./src/data/database.db'); db.prepare('UPDATE users SET role = ? WHERE email = ?').run('admin', '$email'); console.log('✅ Usuario convertido a admin'); db.close();"

{```

  "message": "Credenciales invalidas"

}### Opción C: Directamente en Base de Datos

```

```powershell

❌ **429 Too Many Requests** - Demasiados intentos:# Si tienes sqlite3 instalado

```jsonsqlite3 .\src\data\database.db "UPDATE users SET role = 'admin' WHERE email = 'admin@passportinc.com';"

{```

  "message": "Demasiados intentos de inicio de sesión. Intente de nuevo en 15 minutos."

}### Después de Convertir en Admin

```

Vuelve a **Postman** y:

---

1. Ejecuta **"4. Login with JWT"** pero cambia el body:

#### 4️⃣ Login con Sesión (Con Estado)```json

{

**Request:**  "email": "admin@passportinc.com",

```  "password": "Admin123456",

Method: POST  "type": "jwt"

URL: http://localhost:3000/auth/login}

```

Headers:

  Content-Type: application/json2. Ahora ejecuta los requests de **ADMIN**:

  X-CSRF-Token: <pega-el-token-csrf-aquí>   - **ADMIN - List Users** → Debe retornar array de usuarios

   - **ADMIN - Delete User** → Elimina usuario por ID

Body (raw JSON):

{---

  "email": "usuario@test.com",

  "password": "password123",## 4. 📝 Verificar Logs

  "type": "session"

}### Ver intentos de autenticación

```

```powershell

**Response Esperada (200 OK):**# Ver últimas 20 líneas del log

```jsonGet-Content ".\src\logs\auth.log" -Tail 20

{

  "message": "Login exitoso (session)",# Ver todo el log

  "user": {Get-Content ".\src\logs\auth.log"

    "id": 1,

    "email": "usuario@test.com",# Ver log en tiempo real (monitoreo continuo)

    "role": "user"Get-Content ".\src\logs\auth.log" -Wait -Tail 10

  }```

}

```**Formato del log:**

```

**Nota:** La cookie `sid` se enviará automáticamente en las respuestas siguientes.2025-10-30 15:30:45 | ÉXITO | user@passportinc.com | IP: ::1

2025-10-30 15:31:12 | FALLO | user@passportinc.com | IP: ::1

---```



### Flujo de Rutas Protegidas (Admin)---



#### 5️⃣ Listar Todos los Usuarios (Requiere Admin)## 5. 🗄️ Verificar Base de Datos



**Request:**### Ver todos los usuarios

```

Method: GET```powershell

URL: http://localhost:3000/admin/users# Script para listar usuarios

node -e "const db = require('better-sqlite3')('./src/data/database.db'); const users = db.prepare('SELECT id, email, role, created_at FROM users').all(); console.table(users); db.close();"

Headers:```

  Authorization: Bearer <pega-el-jwt-token-aquí>

  Content-Type: application/json**Salida esperada:**

``````

┌─────────┬────┬──────────────────────────┬─────────┬─────────────────────┐

**Response Esperada (200 OK) - Si eres admin:**│ (index) │ id │         email            │  role   │     created_at      │

```json├─────────┼────┼──────────────────────────┼─────────┼─────────────────────┤

[│    0    │ 1  │ user@passportinc.com     │ 'user'  │ '2025-10-30 15:30'  │

  {│    1    │ 2  │ admin@passportinc.com    │ 'admin' │ '2025-10-30 15:31'  │

    "id": 1,└─────────┴────┴──────────────────────────┴─────────┴─────────────────────┘

    "email": "admin@test.com",```

    "role": "admin"

  },### Ver sesiones activas

  {

    "id": 2,```powershell

    "email": "usuario@test.com",# Script para listar sesiones

    "role": "user"node -e "const db = require('better-sqlite3')('./src/data/database.db'); const sessions = db.prepare('SELECT session_id, user_id, expires_at FROM sessions').all(); console.table(sessions); db.close();"

  }```

]

```### Contar usuarios por rol



**Posibles Errores:**```powershell

# Script para contar usuarios

❌ **401 Unauthorized** - Token no proporcionado:node -e "const db = require('better-sqlite3')('./src/data/database.db'); const stats = db.prepare('SELECT role, COUNT(*) as total FROM users GROUP BY role').all(); console.table(stats); db.close();"

```json```

{

  "message": "Token no proporcionado"---

}

```## 6. 🔧 Pruebas Manuales con PowerShell



❌ **403 Forbidden** - No eres admin:Si prefieres probar con comandos directos en PowerShell:

```json

{### 1️⃣ Obtener CSRF Token

  "message": "Acceso denegado: permisos insuficientes"

}```powershell

```$csrf = Invoke-RestMethod -Uri "http://localhost:3000/auth/csrf-token" -Method Get -SessionVariable session

$csrfToken = $csrf.csrfToken

❌ **403 Forbidden** - Token expirado:Write-Host "✅ CSRF Token: $csrfToken" -ForegroundColor Green

```json```

{

  "message": "Token inválido o expirado"### 2️⃣ Registrar Usuario

}

``````powershell

$headers = @{

---    "Content-Type" = "application/json"

    "X-CSRF-Token" = $csrfToken

#### 6️⃣ Eliminar Usuario (Requiere Admin)}



**Request:**$body = @{

```    email = "test@passportinc.com"

Method: DELETE    password = "Test123456"

URL: http://localhost:3000/admin/users/2} | ConvertTo-Json



Headers:$response = Invoke-RestMethod -Uri "http://localhost:3000/auth/register" -Method Post -Headers $headers -Body $body -WebSession $session

  Authorization: Bearer <pega-el-jwt-token-aquí>Write-Host "✅ Usuario registrado: $($response.message)" -ForegroundColor Green

  X-CSRF-Token: <pega-el-token-csrf-aquí>```

  Content-Type: application/json

```### 3️⃣ Login con JWT



**Response Esperada (200 OK):**```powershell

```json$bodyLogin = @{

{    email = "test@passportinc.com"

  "message": "Usuario eliminado"    password = "Test123456"

}    type = "jwt"

```} | ConvertTo-Json



**Posibles Errores:**$loginResponse = Invoke-RestMethod -Uri "http://localhost:3000/auth/login" -Method Post -Headers $headers -Body $bodyLogin -WebSession $session

$jwtToken = $loginResponse.token

❌ **400 Bad Request** - ID inválido:Write-Host "✅ JWT Token obtenido: $jwtToken" -ForegroundColor Green

```json```

{

  "message": "Id invalido"### 4️⃣ Login con Session

}

``````powershell

$bodySession = @{

❌ **403 Forbidden** - Sin permisos o CSRF inválido    email = "test@passportinc.com"

    password = "Test123456"

---    type = "session"

} | ConvertTo-Json

#### 7️⃣ Logout

$sessionResponse = Invoke-RestMethod -Uri "http://localhost:3000/auth/login" -Method Post -Headers $headers -Body $bodySession -WebSession $session

**Request:**Write-Host "✅ Sesión iniciada: $($sessionResponse.message)" -ForegroundColor Green

``````

Method: POST

URL: http://localhost:3000/auth/logout### 5️⃣ Acceder a Ruta Protegida (Admin)



Headers:```powershell

  X-CSRF-Token: <pega-el-token-csrf-aquí>$authHeaders = @{

  Content-Type: application/json    "Authorization" = "Bearer $jwtToken"

```}



**Response Esperada (200 OK):**try {

```json    $users = Invoke-RestMethod -Uri "http://localhost:3000/admin/users" -Method Get -Headers $authHeaders

{    Write-Host "✅ Usuarios obtenidos:" -ForegroundColor Green

  "message": "Sesión cerrada"    $users | Format-Table

}} catch {

```    Write-Host "❌ Acceso denegado (403): No eres admin" -ForegroundColor Red

}

---```



## 🎯 Casos de Prueba Específicos### 6️⃣ Logout



### Test 1: Validación de Email```powershell

$logoutResponse = Invoke-RestMethod -Uri "http://localhost:3000/auth/logout" -Method Post -Headers $headers -WebSession $session

**Request:**Write-Host "✅ Sesión cerrada: $($logoutResponse.message)" -ForegroundColor Green

```json```

{

  "email": "email-invalido",---

  "password": "123456"

}## 7. 🧹 Limpiar Todo (Reset Completo)

```

Si quieres empezar de cero:

**Response Esperada (400):**

```json```powershell

{# Detener servidor (Ctrl + C)

  "errors": [

    {# Eliminar base de datos y logs

      "msg": "Correo electrónico inválido",Remove-Item ".\src\data\database.db" -Force

      "param": "email"Remove-Item ".\src\logs\auth.log" -Force

    }

  ]# Volver a iniciar servidor

}npm start

``````



------



### Test 2: Contraseña Muy Corta## 8. ✅ Checklist de Validación



**Request:**Marca cada funcionalidad probada:

```json

{- [ ] **1. Bcrypt**: Contraseñas hasheadas en BD

  "email": "test@test.com",- [ ] **2. JWT**: Login retorna token válido

  "password": "123"- [ ] **3. Dual Auth**: Login funciona con `type: "jwt"` y `type: "session"`

}- [ ] **4. RBAC**: Admin puede acceder a `/admin/*`, user no

```- [ ] **5. CSRF**: Requests POST/DELETE requieren X-CSRF-Token

- [ ] **6. Rate Limit**: 5 intentos fallidos bloquean por 15 minutos

**Response Esperada (400):**- [ ] **7. XSS Protection**: Inputs son sanitizados (trim + escape)

```json- [ ] **8. Helmet**: Headers de seguridad presentes

{- [ ] **9. Secure Cookies**: Cookie `sid` tiene httpOnly, secure, sameSite

  "errors": [- [ ] **10. Logging**: Intentos registrados en `src/logs/auth.log`

    {

      "msg": "La contraseña debe tener al menos 6 caracteres",---

      "param": "password"

    }## 9. 🐛 Troubleshooting

  ]

}### Error: "Cannot open database"

``````powershell

# Crear directorios manualmente

---New-Item -Path "src\data" -ItemType Directory -Force

New-Item -Path "src\logs" -ItemType Directory -Force

### Test 3: Rate Limitingnpm start

```

Haz 6 intentos de login seguidos con credenciales incorrectas.

### Error: "CSRF token mismatch"

**En el 6to intento, respuesta esperada (429):**```powershell

```json# Obtener nuevo token CSRF

{# En Postman: Volver a ejecutar Request #1

  "message": "Demasiados intentos de inicio de sesión. Intente de nuevo en 15 minutos."```

}

```### Error: "User already exists"

```powershell

---# Cambiar el email en el body o eliminar la BD

Remove-Item ".\src\data\database.db" -Force

### Test 4: Token JWT Expiradonpm start

```

Espera 1 hora (o modifica JWT_EXP en .env a 10s para pruebas rápidas).

### Error: "Rate limit exceeded"

**Request:**```powershell

```# Esperar 15 minutos o reiniciar servidor

GET /admin/users# Ctrl + C, luego npm start

Authorization: Bearer <token-expirado>```

```

---

**Response Esperada (403):**

```json## 10. 📊 Resultados Esperados

{

  "message": "Token inválido o expirado"### ✅ **Todos los tests pasando en Postman**

}

```| Request | Status | Test Result |

|---------|--------|-------------|

---| 1. Get CSRF Token | 200 | ✅ Token received |

| 2. Register User | 201 | ✅ User created |

### Test 5: Acceso sin Token| 3. Register Admin | 201 | ✅ User created |

| 4. Login JWT | 200 | ✅ Token received |

**Request:**| 5. Login Session | 200 | ✅ Cookie set |

```| 6. Try Admin (user) | 403 | ✅ Access denied |

GET /admin/users| 7. Login Failed | 401 | ✅ Unauthorized |

(Sin header Authorization)| 8. Logout | 200 | ✅ Session closed |

```| ADMIN - List Users | 200 | ✅ Array returned |

| ADMIN - Delete User | 200 | ✅ User deleted |

**Response Esperada (401):**

```json---

{

  "message": "Token no proporcionado"## 📞 Resumen de Comandos Rápidos

}

``````powershell

# Iniciar servidor

---npm start



## 📊 Collection de Postman# Convertir en admin

node make-admin.js

### Estructura Recomendada

# Ver logs

```Get-Content ".\src\logs\auth.log" -Tail 20

📁 PassPort Inc API

├── 📁 Auth# Ver usuarios

│   ├── GET  CSRF Tokennode -e "const db = require('better-sqlite3')('./src/data/database.db'); console.table(db.prepare('SELECT id, email, role FROM users').all()); db.close();"

│   ├── POST Register

│   ├── POST Login (JWT)# Reset completo

│   ├── POST Login (Session)Remove-Item ".\src\data\database.db", ".\src\logs\auth.log" -Force; npm start

│   └── POST Logout```

├── 📁 Admin

│   ├── GET  List Users---

│   └── DELETE Delete User

└── 📁 Tests🎉 **¡Todo listo!** Ahora tienes todos los scripts y comandos para probar tu API completa.

    ├── ❌ Invalid Email
    ├── ❌ Short Password
    ├── ❌ Rate Limiting
    ├── ❌ Expired Token
    └── ❌ No Token
```

### Variables de Entorno en Postman

Crea un Environment llamado "PassPort Local":

```
base_url: http://localhost:3000
csrf_token: (se actualiza automáticamente con scripts)
jwt_token: (se actualiza automáticamente con scripts)
```

### Scripts Útiles

**En "Login (JWT)" → Tests tab:**
```javascript
// Guardar el token automáticamente
if (pm.response.code === 200) {
    const response = pm.response.json();
    pm.environment.set("jwt_token", response.token);
}
```

**En "CSRF Token" → Tests tab:**
```javascript
// Guardar el CSRF token automáticamente
if (pm.response.code === 200) {
    const response = pm.response.json();
    pm.environment.set("csrf_token", response.csrfToken);
}
```

**Usar variables en headers:**
```
X-CSRF-Token: {{csrf_token}}
Authorization: Bearer {{jwt_token}}
```

---

## 🔧 Tips para Debugging

### Ver Logs del Servidor

El servidor muestra logs en la terminal:
```
🔍 Login attempt: usuario@test.com - SUCCESS
🔍 Login attempt: usuario@test.com - FAIL
```

### Ver Logs de Autenticación

Revisa el archivo `src/logs/auth.log`:
```
2025-11-06T10:30:00.000Z | ::1 | usuario@test.com | SUCCESS
2025-11-06T10:31:00.000Z | ::1 | usuario@test.com | FAIL
```

### Reiniciar Rate Limiter

Si quedaste bloqueado por rate limiting:
```bash
# Reiniciar servidor (en desarrollo)
Ctrl+C
npm start
```

### Verificar Base de Datos

```bash
# Abrir SQLite
sqlite3 src/data/database.db

# Ver usuarios
SELECT * FROM users;

# Ver sesiones
SELECT * FROM sessions;

# Salir
.exit
```

---

## ✅ Checklist de Pruebas

- [ ] Obtener token CSRF
- [ ] Registrar usuario nuevo
- [ ] Intentar registrar usuario duplicado (409)
- [ ] Login con JWT (credenciales correctas)
- [ ] Login con JWT (credenciales incorrectas → 401)
- [ ] Login con Session
- [ ] Acceder a /admin/users sin token (401)
- [ ] Acceder a /admin/users con token de user (403)
- [ ] Crear usuario admin manualmente en DB
- [ ] Acceder a /admin/users con token de admin (200)
- [ ] Eliminar usuario con admin
- [ ] Logout
- [ ] Probar rate limiting (6 intentos de login)
- [ ] Validación de email inválido
- [ ] Validación de contraseña corta

---

## 🚨 Troubleshooting

### Error: "CSRF token mismatch"
- Obtén un nuevo token CSRF
- Asegúrate de incluir el header `X-CSRF-Token`

### Error: "Token no proporcionado"
- Incluye el header `Authorization: Bearer <token>`

### Error: "Cannot POST /auth/register"
- Verifica que el servidor esté corriendo
- Verifica la URL correcta

### Error: "Too many requests"
- Espera 15 minutos o reinicia el servidor

---

## 📖 Recursos Adicionales

- [README.md](README.md) - Documentación general
- [ARQUITECTURA.md](ARQUITECTURA.md) - Arquitectura del sistema
- Postman Collections: Exporta y comparte tu collection

---

¡Feliz testing! 🎉
