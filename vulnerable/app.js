// ⚠️  TIENDA VULNERABLE — escrita MAL a propósito para la exposición.
//     Nunca uses este código en un proyecto real.
//     Cada fallo está marcado con la categoría del OWASP Top 10:2025.
const express = require('express');
const { crearBaseDeDatos, paginaInicio } = require('../comun/datos');

// A04 Fallas criptográficas: las contraseñas se guardan en TEXTO PLANO.
// A02 Configuración insegura: el admin usa la clave por defecto "admin".
const db = crearBaseDeDatos([
  { id: 1, usuario: 'ana', clave: 'Ana#Segura2026', rol: 'cliente' },
  { id: 2, usuario: 'luis', clave: 'luis2026', rol: 'cliente' },
  { id: 3, usuario: 'admin', clave: 'admin', rol: 'admin' },
]);

const registro = []; // A09: "registro" de eventos (mal hecho, ver /api/login)

const app = express();
// A02: Express anuncia su tecnología con la cabecera X-Powered-By (no se desactiva).
app.use(express.json());

// ---------------------------------------------------------------- sesiones
// A07 Fallas de autenticación + A08 Fallas de integridad:
// el "token" es solo el usuario en Base64, SIN firma y SIN vencimiento.
// Cualquiera puede decodificarlo, cambiar rol:"cliente" por rol:"admin" y volverlo a codificar.
function crearToken(u) {
  return Buffer.from(JSON.stringify({ id: u.id, usuario: u.usuario, rol: u.rol })).toString('base64');
}
function leerToken(req) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  return JSON.parse(Buffer.from(t, 'base64').toString()); // lanza error si el token está mal formado
}

function autenticado(req, res, next) {
  try { req.usuario = leerToken(req); next(); }
  catch { res.status(401).json({ error: 'Inicia sesión' }); }
}

// A10 Manejo incorrecto de condiciones excepcionales ("fail open"):
// si ocurre un error al revisar el token, el catch DEJA PASAR la petición.
function soloAdmin(req, res, next) {
  try {
    const u = leerToken(req);
    if (u.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
    next();
  } catch (e) {
    next(); // "si algo falla, que siga" -> un token roto abre la puerta de admin
  }
}

// ---------------------------------------------------------------- rutas
app.get('/', (req, res) => res.send(paginaInicio('Tienda VULNERABLE', '#c0392b')));

// A05 Inyección SQL: la consulta se arma concatenando lo que escribe el usuario.
//     usuario = admin' --   comenta el resto de la consulta y entra sin clave.
// A07: no hay límite de intentos, se puede probar contraseñas sin parar (fuerza bruta).
app.post('/api/login', (req, res) => {
  const { usuario, clave } = req.body;
  const sql = `SELECT * FROM usuarios WHERE usuario = '${usuario}' AND clave = '${clave}'`;
  const u = db.prepare(sql).get();
  if (!u) return res.status(401).json({ error: 'Credenciales inválidas' }); // A09: el fallo no se registra
  registro.push(`login OK usuario=${usuario} clave=${clave}`); // A09: ¡registra la contraseña!
  res.json({ token: crearToken(u), usuario: u.usuario, rol: u.rol });
});

// A05 Inyección (XSS reflejado): lo que se busca se pega tal cual en el HTML.
app.get('/buscar', (req, res) => {
  const q = req.query.q || '';
  const filas = db.prepare('SELECT nombre, precio FROM productos WHERE nombre LIKE ?').all(`%${q}%`);
  res.send(`<h2>Resultados para: ${q}</h2><ul>${filas.map((p) => `<li>${p.nombre} - $${p.precio}</li>`).join('')}</ul>`);
});

// A01 Control de acceso roto (IDOR): devuelve CUALQUIER pedido, sin revisar de quién es.
app.get('/api/pedidos/:id', autenticado, (req, res) => {
  const pedido = db.prepare('SELECT * FROM pedidos WHERE id = ?').get(Number(req.params.id));
  if (!pedido) return res.status(404).json({ error: 'No existe' });
  res.json(pedido);
});

// A06 Diseño inseguro: el servidor confía en el PRECIO que envía el navegador.
app.post('/api/comprar', autenticado, (req, res) => {
  const { productoId, cantidad, precio } = req.body;
  const p = db.prepare('SELECT * FROM productos WHERE id = ?').get(productoId);
  res.json({ mensaje: 'Compra realizada', producto: p.nombre, cantidad, total: precio * cantidad });
});

// Rutas de administración (protegidas por el soloAdmin defectuoso).
app.get('/api/admin/usuarios', soloAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, usuario, rol FROM usuarios').all());
});
// A04: el respaldo de la base de datos trae las contraseñas legibles.
app.get('/api/admin/respaldo', soloAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM usuarios').all());
});
// A09: el único registro que existe no tiene fallos, horas ni alertas.
app.get('/api/admin/auditoria', soloAdmin, (req, res) => res.json(registro));

// A02: endpoint de depuración olvidado en producción, expone secretos.
app.get('/debug', (req, res) => {
  res.json({ entorno: 'produccion', claveBaseDatos: 'root:SuperSecreta123', node: process.version });
});

// A02: los errores muestran el stack trace completo (rutas internas del servidor).
app.use((err, req, res, next) => res.status(500).send(err.stack));

function iniciar(puerto = 3000) {
  return app.listen(puerto, () => console.log(`🔓 Tienda VULNERABLE en http://localhost:${puerto}`));
}
if (require.main === module) iniciar(Number(process.env.PORT) || 3000);
module.exports = { iniciar };
