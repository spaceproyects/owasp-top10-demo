// Lanza los 10 ataques del OWASP Top 10:2025 contra las dos tiendas y compara.
// Uso:  npm run ataque
const fs = require('node:fs');
const path = require('node:path');
const vulnerable = require('../vulnerable/app');
const seguro = require('../seguro/app');

const TIENDAS = [
  { nombre: 'VULNERABLE', url: 'http://localhost:3000', claveAdmin: 'admin' },
  { nombre: 'SEGURA', url: 'http://localhost:3001', claveAdmin: process.env.ADMIN_CLAVE || 'Adm!n-Demo-7f3K-2026' },
];

// ---------------------------------------------------------------- utilidades
async function pedir(base, ruta, { metodo = 'GET', cuerpo, token, crudo } = {}) {
  const headers = {};
  if (cuerpo !== undefined || crudo !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;
  const r = await fetch(base + ruta, {
    method: metodo, headers,
    body: crudo !== undefined ? crudo : cuerpo !== undefined ? JSON.stringify(cuerpo) : undefined,
  });
  const texto = await r.text();
  let json = null;
  try { json = JSON.parse(texto); } catch {}
  return { status: r.status, texto, json, headers: r.headers };
}
async function login(base, usuario, clave) {
  const r = await pedir(base, '/api/login', { metodo: 'POST', cuerpo: { usuario, clave } });
  return r.json && r.json.token;
}
const recortar = (s, n = 90) => (s.length > n ? s.slice(0, n) + '…' : s);

// Cada ataque devuelve { exito: true si el ataque FUNCIONÓ, detalle }
const ATAQUES = [
  {
    id: 'A01', nombre: 'Control de acceso roto',
    como: 'Ana (cliente) pide el pedido #2, que es de Luis',
    async ejecutar(t) {
      const token = await login(t.url, 'ana', 'Ana#Segura2026');
      const r = await pedir(t.url, '/api/pedidos/2', { token });
      return r.status === 200
        ? { exito: true, detalle: `Ve la dirección de Luis: ${r.json.direccion}` }
        : { exito: false, detalle: `HTTP ${r.status} ${r.json.error}` };
    },
  },
  {
    id: 'A02', nombre: 'Configuración de seguridad incorrecta',
    como: 'Busca /debug, la cabecera X-Powered-By y errores con stack trace',
    async ejecutar(t) {
      const hallazgos = [];
      const d = await pedir(t.url, '/debug');
      if (d.status === 200) hallazgos.push(`/debug expone "${d.json.claveBaseDatos}"`);
      if (d.headers.get('x-powered-by')) hallazgos.push(`X-Powered-By: ${d.headers.get('x-powered-by')}`);
      const e = await pedir(t.url, '/api/login', { metodo: 'POST', crudo: '{json roto' });
      if (/\n\s+at /.test(e.texto)) hallazgos.push('el error muestra el stack trace');
      return hallazgos.length
        ? { exito: true, detalle: hallazgos.join(' | ') }
        : { exito: false, detalle: `/debug -> ${d.status}, sin X-Powered-By, error genérico: ${recortar(e.texto, 60)}` };
    },
  },
  {
    id: 'A03', nombre: 'Fallas en la cadena de suministro de software',
    como: 'Revisa cómo se declaran las dependencias (versiones fijas + lockfile)',
    async ejecutar(t) {
      const raiz = path.join(__dirname, '..');
      const archivo = t.nombre === 'VULNERABLE' ? 'dependencias/package.vulnerable.json' : 'package.json';
      const pkg = JSON.parse(fs.readFileSync(path.join(raiz, archivo), 'utf8'));
      const sueltas = Object.entries(pkg.dependencies || {}).filter(([, v]) => !/^\d+\.\d+\.\d+$/.test(v));
      const lock = t.nombre === 'SEGURA' && fs.existsSync(path.join(raiz, 'package-lock.json'));
      return sueltas.length || !lock
        ? { exito: true, detalle: `Versiones sin fijar: ${sueltas.map(([n, v]) => `${n}@${v}`).join(', ') || '-'}; lockfile: ${lock ? 'sí' : 'NO'}` }
        : { exito: false, detalle: `Todas las versiones fijas (${Object.entries(pkg.dependencies).map(([n, v]) => `${n}@${v}`).join(', ')}) y package-lock.json presente` };
    },
  },
  {
    id: 'A04', nombre: 'Fallas criptográficas',
    como: 'Se filtra el respaldo de la base de datos: ¿se leen las contraseñas?',
    async ejecutar(t) {
      const token = await login(t.url, 'admin', t.claveAdmin);
      const r = await pedir(t.url, '/api/admin/respaldo', { token });
      const ana = r.json.find((u) => u.usuario === 'ana');
      return ana.clave === 'Ana#Segura2026'
        ? { exito: true, detalle: `Contraseña de Ana en texto plano: "${ana.clave}"` }
        : { exito: false, detalle: `Solo se ve un hash: ${recortar(ana.clave, 50)}` };
    },
  },
  {
    id: 'A05', nombre: 'Inyección (SQL y XSS)',
    como: "Login con usuario  admin' --  y búsqueda con <script>",
    async ejecutar(t) {
      const hallazgos = [];
      const r = await pedir(t.url, '/api/login', { metodo: 'POST', cuerpo: { usuario: "admin' --", clave: 'cualquiera' } });
      if (r.status === 200) hallazgos.push(`SQLi: entró como "${r.json.usuario}" sin clave`);
      const x = await pedir(t.url, '/buscar?q=' + encodeURIComponent('<script>alert("hackeado")</script>'));
      if (x.texto.includes('<script>')) hallazgos.push('XSS: el <script> llega intacto al navegador');
      return hallazgos.length
        ? { exito: true, detalle: hallazgos.join(' | ') }
        : { exito: false, detalle: `SQLi -> HTTP ${r.status}; XSS escapado como &lt;script&gt;` };
    },
  },
  {
    id: 'A06', nombre: 'Diseño inseguro',
    como: 'Compra el portátil de $3.500.000 enviando precio: 1',
    async ejecutar(t) {
      const token = await login(t.url, 'ana', 'Ana#Segura2026');
      const r = await pedir(t.url, '/api/comprar', { metodo: 'POST', token, cuerpo: { productoId: 1, cantidad: 1, precio: 1 } });
      return r.json.total < 3500000
        ? { exito: true, detalle: `Pagó $${r.json.total} por un ${r.json.producto}` }
        : { exito: false, detalle: `El servidor cobró el precio real: $${r.json.total.toLocaleString('es-CO')}` };
    },
  },
  {
    id: 'A07', nombre: 'Fallas de autenticación',
    como: 'Fuerza bruta contra "luis" con 6 contraseñas comunes',
    async ejecutar(t) {
      const lista = ['123456', 'password', 'qwerty', 'admin', '12345678', 'luis2026'];
      for (const [i, clave] of lista.entries()) {
        const r = await pedir(t.url, '/api/login', { metodo: 'POST', cuerpo: { usuario: 'luis', clave } });
        if (r.status === 200) return { exito: true, detalle: `Adivinó la clave "${clave}" en el intento ${i + 1}` };
        if (r.status === 429) return { exito: false, detalle: `Cuenta bloqueada en el intento ${i + 1}: ${r.json.error}` };
      }
      return { exito: false, detalle: 'No adivinó la clave' };
    },
  },
  {
    id: 'A08', nombre: 'Fallas de integridad de software o datos',
    como: 'Falsifica un token cambiando rol "cliente" por "admin"',
    async ejecutar(t) {
      const real = await login(t.url, 'ana', 'Ana#Segura2026');
      let falso;
      if (real.includes('.')) { // token firmado: se cambia el contenido pero se conserva la firma vieja
        const [datos, firma] = real.split('.');
        const p = JSON.parse(Buffer.from(datos, 'base64url').toString());
        falso = Buffer.from(JSON.stringify({ ...p, rol: 'admin' })).toString('base64url') + '.' + firma;
      } else {
        const p = JSON.parse(Buffer.from(real, 'base64').toString());
        falso = Buffer.from(JSON.stringify({ ...p, rol: 'admin' })).toString('base64');
      }
      const r = await pedir(t.url, '/api/admin/usuarios', { token: falso });
      return r.status === 200
        ? { exito: true, detalle: `Con el token falso lista ${r.json.length} usuarios del panel de admin` }
        : { exito: false, detalle: `HTTP ${r.status}: la firma no coincide, token rechazado` };
    },
  },
  {
    id: 'A09', nombre: 'Fallas de registro y alertas',
    como: 'Después del ataque de fuerza bruta, ¿quedó registro y alerta?',
    async ejecutar(t) {
      const token = await login(t.url, 'admin', t.claveAdmin);
      const r = await pedir(t.url, '/api/admin/auditoria', { token });
      const texto = JSON.stringify(r.json);
      const fallos = (texto.match(/login_fallido/g) || []).length;
      const alerta = texto.includes('ALERTA');
      const conClaves = r.json.find((l) => typeof l === 'string' && l.includes('clave='));
      return !fallos || !alerta || conClaves
        ? { exito: true, detalle: `Fallos registrados: ${fallos}, alerta: ${alerta ? 'sí' : 'NO'}${conClaves ? ` | y guarda claves: "${conClaves}"` : ''}` }
        : { exito: false, detalle: `Fallos registrados: ${fallos}, alerta de fuerza bruta: sí, sin contraseñas en el log` };
    },
  },
  {
    id: 'A10', nombre: 'Manejo incorrecto de condiciones excepcionales',
    como: 'Envía un token roto ("%%%") al panel de admin',
    async ejecutar(t) {
      const r = await pedir(t.url, '/api/admin/usuarios', { token: '%%%roto' });
      return r.status === 200
        ? { exito: true, detalle: 'El error se tragó en un catch y DEJÓ PASAR al panel de admin (fail open)' }
        : { exito: false, detalle: `HTTP ${r.status}: ante el error se niega el acceso (fail closed)` };
    },
  },
];

// ---------------------------------------------------------------- ejecución
(async () => {
  const servidores = [vulnerable.iniciar(3000), seguro.iniciar(3001)];
  await new Promise((r) => setTimeout(r, 300));
  console.log('\n══════════ OWASP Top 10:2025 — ataque en vivo ══════════\n');
  let resumen = { VULNERABLE: 0, SEGURA: 0 };
  try {
    for (const a of ATAQUES) {
      console.log(`▶ ${a.id} ${a.nombre}`);
      console.log(`  Ataque: ${a.como}`);
      for (const t of TIENDAS) {
        let res;
        try { res = await a.ejecutar(t); } catch (e) { res = { exito: false, detalle: `error en el ataque: ${e.message}` }; }
        if (res.exito) resumen[t.nombre]++;
        const marca = res.exito ? '❌ ATAQUE EXITOSO ' : '✅ BLOQUEADO      ';
        console.log(`   ${t.nombre.padEnd(10)} ${marca} ${res.detalle}`);
      }
      console.log('');
    }
  } finally {
    servidores.forEach((s) => s.close());
  }
  console.log('══════════════════════════ RESUMEN ══════════════════════════');
  console.log(`  Tienda VULNERABLE: ${resumen.VULNERABLE}/10 ataques funcionaron`);
  console.log(`  Tienda SEGURA:     ${resumen.SEGURA}/10 ataques funcionaron\n`);
})();
