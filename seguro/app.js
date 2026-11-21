// ✅ TIENDA SEGURA — la misma tienda, con cada fallo del OWASP Top 10:2025 corregido.
//    Compárala línea por línea con vulnerable/app.js.
const crypto = require('node:crypto');
const express = require('express');
const { crearBaseDeDatos, paginaInicio } = require('../comun/datos');

// A04 Fallas criptográficas -> las contraseñas se guardan con scrypt + sal aleatoria.
function hashClave(clave) {
  const sal = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(clave, sal, 64).toString('hex');
  return `scrypt$${sal}$${hash}`;
}
function verificarClave(clave, guardada) {
  const [, sal, hash] = guardada.split('$');
  const calculado = crypto.scryptSync(clave, sal, 64);
  return crypto.timingSafeEqual(calculado, Buffer.from(hash, 'hex'));
}

// A02 -> sin claves por defecto: la del admin viene de una variable de entorno.
// (El valor de respaldo existe solo para que la demo funcione sin configurar nada.)
const CLAVE_ADMIN = process.env.ADMIN_CLAVE || 'Adm!n-Demo-7f3K-2026';
const db = crearBaseDeDatos([
  { id: 1, usuario: 'ana', clave: hashClave('Ana#Segura2026'), rol: 'cliente' },
  { id: 2, usuario: 'luis', clave: hashClave('luis2026'), rol: 'cliente' },
  { id: 3, usuario: 'admin', clave: hashClave(CLAVE_ADMIN), rol: 'admin' },
]);

// A08 Integridad -> los tokens se FIRMAN con HMAC y una clave secreta del servidor.
const SECRETO = process.env.TOKEN_SECRETO || crypto.randomBytes(32).toString('hex');
const DURACION_MS = 30 * 60 * 1000; // A07 -> la sesión vence a los 30 minutos

function firmar(datos) {
  return crypto.createHmac('sha256', SECRETO).update(datos).digest('base64url');
}
function crearToken(u) {
  const datos = Buffer.from(JSON.stringify({ id: u.id, rol: u.rol, vence: Date.now() + DURACION_MS })).toString('base64url');
  return `${datos}.${firmar(datos)}`;
}
function leerToken(req) {
  const t = (req.headers.authorization || '').replace('Bearer ', '');
  const [datos, firma] = t.split('.');
  if (!datos || !firma) throw new Error('token mal formado');
  const esperada = Buffer.from(firmar(datos));
  const recibida = Buffer.from(firma);
  if (esperada.length !== recibida.length || !crypto.timingSafeEqual(esperada, recibida)) {
    throw new Error('firma inválida'); // alguien modificó el token
  }
  const payload = JSON.parse(Buffer.from(datos, 'base64url').toString());
  if (Date.now() > payload.vence) throw new Error('token vencido');
  return payload;
}

// A09 Registro y alertas -> se registra cada evento de seguridad, con hora e IP,
// SIN contraseñas, y se lanza una ALERTA cuando hay muchos fallos seguidos.
const registro = [];
function registrar(evento, datos = {}) {
  const linea = { fecha: new Date().toISOString(), evento, ...datos };
  registro.push(linea);
  if (evento === 'ALERTA') console.warn('🚨', JSON.stringify(linea));
}

const app = express();
app.disable('x-powered-by'); // A02 -> no anunciar la tecnología del servidor
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => { // A02 -> cabeceras de seguridad
  res.set({
    'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
  });
  next();
});

// A10 -> "fail closed": si algo falla al revisar el token, se NIEGA el acceso.
function autenticado(req, res, next) {
  try { req.usuario = leerToken(req); next(); }
  catch (e) {
    registrar('token_rechazado', { motivo: e.message, ip: req.ip });
    res.status(401).json({ error: 'Sesión inválida' });
  }
}
function soloAdmin(req, res, next) {
  autenticado(req, res, () => {
    if (req.usuario.rol !== 'admin') {
      registrar('acceso_denegado', { usuarioId: req.usuario.id, ruta: req.path });
      return res.status(403).json({ error: 'Solo administradores' });
    }
    next();
  });
}

// A07 -> bloqueo tras 5 intentos fallidos (frena la fuerza bruta).
const MAX_INTENTOS = 5;
const BLOQUEO_MS = 15 * 60 * 1000;
const intentos = new Map(); // usuario -> { fallos, bloqueadoHasta }

app.get('/', (req, res) => res.send(paginaInicio('Tienda SEGURA', '#1e8449')));

app.post('/api/login', (req, res) => {
  const { usuario, clave } = req.body || {};
  if (typeof usuario !== 'string' || typeof clave !== 'string') {
    return res.status(400).json({ error: 'Datos incompletos' });
  }
  const estado = intentos.get(usuario) || { fallos: 0, bloqueadoHasta: 0 };
  if (Date.now() < estado.bloqueadoHasta) {
    registrar('login_bloqueado', { usuario, ip: req.ip });
    return res.status(429).json({ error: 'Cuenta bloqueada temporalmente. Intenta en 15 minutos.' });
  }

  // A05 Inyección -> consulta PARAMETRIZADA: el "?" nunca se interpreta como SQL.
  const u = db.prepare('SELECT * FROM usuarios WHERE usuario = ?').get(usuario);
  if (!u || !verificarClave(clave, u.clave)) {
    estado.fallos += 1;
    registrar('login_fallido', { usuario, ip: req.ip, fallos: estado.fallos });
    if (estado.fallos >= MAX_INTENTOS) {
      estado.bloqueadoHasta = Date.now() + BLOQUEO_MS;
      registrar('ALERTA', { mensaje: `Posible fuerza bruta contra "${usuario}"`, ip: req.ip });
    }
    intentos.set(usuario, estado);
    return res.status(401).json({ error: 'Credenciales inválidas' });
  }
  intentos.delete(usuario);
  registrar('login_ok', { usuario, ip: req.ip });
  res.json({ token: crearToken(u), usuario: u.usuario, rol: u.rol });
});

// A05 -> se escapan los caracteres especiales antes de meterlos en el HTML.
function escaparHtml(texto) {
  return String(texto).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}
app.get('/buscar', (req, res) => {
  const q = String(req.query.q || '');
  const filas = db.prepare('SELECT nombre, precio FROM productos WHERE nombre LIKE ?').all(`%${q}%`);
  res.send(`<h2>Resultados para: ${escaparHtml(q)}</h2><ul>${filas.map((p) => `<li>${escaparHtml(p.nombre)} - $${p.precio}</li>`).join('')}</ul>`);
});

// A01 Control de acceso -> el pedido debe pertenecer al usuario que lo pide.
app.get('/api/pedidos/:id', autenticado, (req, res) => {
  const pedido = db.prepare('SELECT * FROM pedidos WHERE id = ? AND usuario_id = ?')
    .get(Number(req.params.id), req.usuario.id);
  if (!pedido) return res.status(404).json({ error: 'No existe' }); // no revela si es de otro
  res.json(pedido);
});

// A06 Diseño seguro -> el precio SIEMPRE sale de la base de datos y la cantidad se valida.
app.post('/api/comprar', autenticado, (req, res) => {
  const { productoId, cantidad } = req.body || {};
  if (!Number.isInteger(cantidad) || cantidad < 1 || cantidad > 10) {
    return res.status(400).json({ error: 'La cantidad debe ser un entero entre 1 y 10' });
  }
  const p = db.prepare('SELECT * FROM productos WHERE id = ?').get(productoId);
  if (!p) return res.status(404).json({ error: 'Producto no encontrado' });
  res.json({ mensaje: 'Compra realizada', producto: p.nombre, cantidad, total: p.precio * cantidad });
});

app.get('/api/admin/usuarios', soloAdmin, (req, res) => {
  res.json(db.prepare('SELECT id, usuario, rol FROM usuarios').all());
});
// A04 -> aunque se filtre el respaldo, solo hay hashes con sal, no contraseñas.
app.get('/api/admin/respaldo', soloAdmin, (req, res) => {
  res.json(db.prepare('SELECT * FROM usuarios').all());
});
app.get('/api/admin/auditoria', soloAdmin, (req, res) => res.json(registro));

// A02 + A10 -> error genérico para el usuario; el detalle se queda en el servidor.
app.use((err, req, res, next) => {
  const id = crypto.randomUUID().slice(0, 8);
  registrar('error_interno', { id, mensaje: err.message });
  res.status(err.status === 400 ? 400 : 500).json({ error: 'Ocurrió un error', referencia: id });
});

function iniciar(puerto = 3001) {
  return app.listen(puerto, () => console.log(`🔒 Tienda SEGURA en http://localhost:${puerto}`));
}
if (require.main === module) iniciar(Number(process.env.PORT) || 3001);
module.exports = { iniciar };
