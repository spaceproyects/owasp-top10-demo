// Datos de ejemplo compartidos por las dos tiendas (vulnerable y segura).
// Base de datos SQLite en memoria (módulo nativo node:sqlite, sin instalar nada).
const { DatabaseSync } = require('node:sqlite');

const PRODUCTOS = [
  { id: 1, nombre: 'Portátil Gamer', precio: 3500000 },
  { id: 2, nombre: 'Audífonos Bluetooth', precio: 180000 },
  { id: 3, nombre: 'Teclado Mecánico', precio: 250000 },
];

// Cada pedido pertenece a un usuario y tiene datos personales (dirección).
const PEDIDOS = [
  { id: 1, usuario_id: 1, producto: 'Audífonos Bluetooth', total: 180000, direccion: 'Calle 5 #12-30, Cali' },
  { id: 2, usuario_id: 2, producto: 'Portátil Gamer', total: 3500000, direccion: 'Carrera 80 #3-15, Cali' },
];

/**
 * Crea la base de datos.
 * @param {Array<{id:number, usuario:string, clave:string, rol:string}>} usuarios
 *        La clave llega YA procesada (texto plano en la app vulnerable, hash en la segura).
 */
function crearBaseDeDatos(usuarios) {
  const db = new DatabaseSync(':memory:');
  db.exec(`
    CREATE TABLE usuarios (id INTEGER PRIMARY KEY, usuario TEXT UNIQUE, clave TEXT, rol TEXT);
    CREATE TABLE productos (id INTEGER PRIMARY KEY, nombre TEXT, precio INTEGER);
    CREATE TABLE pedidos (id INTEGER PRIMARY KEY, usuario_id INTEGER, producto TEXT, total INTEGER, direccion TEXT);
  `);
  const insU = db.prepare('INSERT INTO usuarios (id, usuario, clave, rol) VALUES (?, ?, ?, ?)');
  for (const u of usuarios) insU.run(u.id, u.usuario, u.clave, u.rol);
  const insP = db.prepare('INSERT INTO productos (id, nombre, precio) VALUES (?, ?, ?)');
  for (const p of PRODUCTOS) insP.run(p.id, p.nombre, p.precio);
  const insO = db.prepare('INSERT INTO pedidos (id, usuario_id, producto, total, direccion) VALUES (?, ?, ?, ?, ?)');
  for (const o of PEDIDOS) insO.run(o.id, o.usuario_id, o.producto, o.total, o.direccion);
  return db;
}

// Página web mínima para mostrar la tienda en vivo durante la exposición.
function paginaInicio(titulo, color) {
  return `<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>${titulo}</title>
<style>
 body{font-family:Arial,sans-serif;max-width:640px;margin:40px auto;padding:0 16px;color:#222}
 h1{color:${color}} form{margin:16px 0;padding:16px;border:1px solid #ddd;border-radius:8px}
 input,button{padding:8px;margin:4px 0;font-size:15px} button{background:${color};color:#fff;border:0;border-radius:4px;cursor:pointer}
 pre{background:#f4f4f4;padding:12px;border-radius:6px;white-space:pre-wrap}
</style></head><body>
<h1>${titulo}</h1>
<form id="login"><b>Iniciar sesión</b><br>
 <input name="usuario" placeholder="usuario"> <input name="clave" type="password" placeholder="clave">
 <button>Entrar</button></form>
<form action="/buscar" method="get"><b>Buscar productos</b><br>
 <input name="q" placeholder="ej: teclado"> <button>Buscar</button></form>
<pre id="salida">Prueba: usuario  admin' --   con cualquier clave</pre>
<script>
document.getElementById('login').onsubmit = async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usuario: f.get('usuario'), clave: f.get('clave') }) });
  document.getElementById('salida').textContent = r.status + '  ' + await r.text();
};
</script></body></html>`;
}

module.exports = { crearBaseDeDatos, paginaInicio, PRODUCTOS };
