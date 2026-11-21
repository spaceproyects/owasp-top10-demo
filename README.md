# OWASP Top 10:2025 — Tienda vulnerable vs. tienda segura

Demo educativa: **la misma tienda online escrita dos veces**.

| Carpeta | Qué es |
|---|---|
| [`vulnerable/app.js`](vulnerable/app.js) | Tienda con los **10 riesgos** del OWASP Top 10:2025, marcados en comentarios (`// A01 ...`) |
| [`seguro/app.js`](seguro/app.js) | La misma tienda con cada riesgo **corregido** |
| [`demo/atacar.js`](demo/atacar.js) | Script que lanza los 10 ataques contra ambas y muestra cuál resiste |
| [`dependencias/`](dependencias/) | Ejemplo de mala gestión de dependencias (A03) |

> ⚠️ El código de `vulnerable/` es inseguro **a propósito**. Úsalo solo para aprender, en tu equipo.

## Cómo ejecutarlo

Requisito: **Node.js 22.13 o superior** (usa la base de datos SQLite que ya trae Node).

```bash
npm install
npm run ataque
```

Resultado esperado:

```
▶ A05 Inyección (SQL y XSS)
  Ataque: Login con usuario  admin' --  y búsqueda con <script>
   VULNERABLE ❌ ATAQUE EXITOSO  SQLi: entró como "admin" sin clave | XSS: el <script> llega intacto al navegador
   SEGURA     ✅ BLOQUEADO       SQLi -> HTTP 401; XSS escapado como &lt;script&gt;
...
  Tienda VULNERABLE: 10/10 ataques funcionaron
  Tienda SEGURA:     0/10 ataques funcionaron
```

### Demo en el navegador

```bash
npm run vulnerable   # http://localhost:3000
npm run seguro       # http://localhost:3001
```

- **Login con inyección SQL:** usuario `admin' --` y cualquier clave → entra en la vulnerable, falla en la segura.
- **XSS:** busca `<img src=x onerror=alert('hackeado')>` → salta la alerta solo en la vulnerable.
- **Configuración expuesta:** abre `http://localhost:3000/debug`.

## Los 10 riesgos y dónde verlos en el código

| # | Riesgo | En la tienda vulnerable | Corrección en la tienda segura |
|---|---|---|---|
| A01 | Control de acceso roto | `/api/pedidos/:id` devuelve pedidos de **otros** usuarios (IDOR) | La consulta exige `usuario_id` = usuario de la sesión |
| A02 | Configuración de seguridad incorrecta | `/debug` con secretos, admin con clave `admin`, cabecera `X-Powered-By`, stack traces | Sin `/debug`, clave por variable de entorno, cabeceras de seguridad, errores genéricos |
| A03 | Fallas en la cadena de suministro | Dependencias con `*`, `latest`, `^` y sin lockfile | Versiones exactas + `package-lock.json` + `npm audit` / `npm ci` |
| A04 | Fallas criptográficas | Contraseñas en **texto plano** | Hash **scrypt** con sal aleatoria |
| A05 | Inyección | SQL armado concatenando texto; HTML sin escapar | Consultas parametrizadas (`?`) y escape de HTML |
| A06 | Diseño inseguro | El servidor confía en el **precio** que manda el navegador | Precio desde la BD y cantidad validada (1–10) |
| A07 | Fallas de autenticación | Intentos ilimitados, token predecible y sin vencimiento | Bloqueo tras 5 fallos, token con vencimiento de 30 min |
| A08 | Fallas de integridad de software o datos | Token = JSON en Base64 **sin firma** → se cambia `rol` a `admin` | Token firmado con **HMAC-SHA256** |
| A09 | Fallas de registro y alertas | No registra fallos y **guarda contraseñas** en el log | Registra cada evento con hora e IP, sin claves, y lanza **alerta** de fuerza bruta |
| A10 | Manejo incorrecto de condiciones excepcionales | Un `catch` que hace `next()` → token roto = acceso de admin (*fail open*) | Ante cualquier error se niega el acceso (*fail closed*) |

## Usuarios de prueba

| Usuario | Clave | Rol |
|---|---|---|
| ana | `Ana#Segura2026` | cliente |
| luis | `luis2026` | cliente |
| admin | `admin` (vulnerable) / `Adm!n-Demo-7f3K-2026` (segura, o la variable `ADMIN_CLAVE`) | admin |

## Referencia

- OWASP Top 10:2025 — https://owasp.org/Top10/2025/
