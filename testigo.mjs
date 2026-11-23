// Testigo externo del registro público de FirmaRED · versión 2 (23 de noviembre de 2026).
// Cada vez que corre: baja la última raíz del registro y comprueba sus sellos con las claves públicas guardadas en este
// repositorio. Una raíz en formato 1 lleva tres sellos (Ed25519, ML-DSA-65, SLH-DSA-SHA2-128s). Una raíz en formato 2 lleva el
// sello compuesto (Ed25519, ML-DSA-87, SLH-DSA-SHA2-256s), todo o nada: su texto firmado nombra las tres claves por id y huella,
// y las tres firmas tienen que verificar; los dos sellos sueltos de la transición se comprueban si vienen, pero no deciden.
// Después del corte (campo formato2 del estado del registro), una raíz que no esté en formato 2 es un problema.
// Comprueba además que la raíz nueva contenga a la anterior que este testigo vio (consistencia RFC 9162) y que las cinco claves
// que el sitio publica sigan siendo las guardadas. No usa ninguna biblioteca: solo el OpenSSL de Node 24 o posterior. Solo lee.
//   node testigo.mjs            corre una vez
//   node testigo.mjs --sitio https://otro   otra dirección del sitio
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const AQUI = dirname(fileURLToPath(import.meta.url));
const SITIO = (process.argv.indexOf('--sitio') > 0 ? process.argv[process.argv.indexOf('--sitio') + 1] : 'https://firmared.com').replace(/\/$/, '');
const CLAVES = existsSync(join(AQUI, 'claves', 'firmared-sello-ed25519.pem')) ? join(AQUI, 'claves') : AQUI, REG = join(AQUI, 'registro');   // las claves, en claves/ o sueltas al lado
const AHORA = new Date().toISOString();
const H = (...b) => { const h = createHash('sha256'); for (const x of b) h.update(x); return h.digest(); };
const hex = (b) => Buffer.from(b).toString('hex');

async function bajar(ruta, texto = false) {
  const r = await fetch(SITIO + ruta, { signal: AbortSignal.timeout(30000), headers: { 'User-Agent': 'testigo-firmared/1 (+github actions)' } });
  if (r.status !== 200) throw new Error(ruta + ' respondió ' + r.status);
  return texto ? r.text() : r.json();
}
const leer = (f, d = null) => { try { return JSON.parse(readFileSync(f, 'utf8')); } catch (e) { return d; } };
const pem = (n) => readFileSync(join(CLAVES, n), 'utf8');
const sello = (clave, canon, firmaB64) => { try { return firmaB64 ? verify(null, canon, createPublicKey(clave), Buffer.from(firmaB64, 'base64')) === true : false; } catch (e) { return false; } };
// la huella de una clave, como la escribe FirmaRED: Ed25519, el SHA-256 de la clave en DER; las poscuánticas, el de los bytes crudos
const LLAVES = { ed25519: ['firmared-sello-ed25519.pem', 32, 'der'], mldsa65: ['firmared-sello-mldsa65.pem', 1952, 'cruda'], slhdsa: ['firmared-sello-slhdsa.pem', 32, 'cruda'], mldsa87: ['firmared-sello-mldsa87.pem', 2592, 'cruda'], slhdsa256s: ['firmared-sello-slhdsa256s.pem', 64, 'cruda'] };
function huellaDe(k) { const [n, largo, modo] = LLAVES[k]; const der = createPublicKey(pem(n)).export({ type: 'spki', format: 'der' }); return createHash('sha256').update(modo === 'der' ? der : der.subarray(der.length - largo)).digest('hex'); }
const IDS = { ed25519: 'did:web:firmared.com#key-ed25519-2026', mldsa87: 'did:web:firmared.com#key-mldsa87-2026', slhdsa256s: 'did:web:firmared.com#key-slhdsa256s-2026' };

// RFC 9162 §2.1.4.2 · la raíz nueva (tamaño n) contiene a la vieja (tamaño m) si la prueba de consistencia cierra por los dos lados
function consistencia(m, n, raizVieja, raizNueva, prueba) {
  if (m === n) return prueba.length === 0 && raizVieja.equals(raizNueva);
  if (m === 0 || m > n || prueba.length === 0) return m === 0 && prueba.length === 0;
  let P = prueba.slice();
  if ((m & (m - 1)) === 0) P = [raizVieja].concat(P);   // m es potencia de dos: el primer nodo es la raíz vieja
  let fn = m - 1, sn = n - 1;
  while ((fn & 1) === 1) { fn >>= 1; sn >>= 1; }
  let fr = P[0], sr = P[0];
  for (const c of P.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) { fr = H(Buffer.from([1]), c, fr); sr = H(Buffer.from([1]), c, sr); while (fn !== 0 && (fn & 1) === 0) { fn >>= 1; sn >>= 1; } }
    else sr = H(Buffer.from([1]), sr, c);
    fn >>= 1; sn >>= 1;
  }
  return sn === 0 && fr.equals(raizVieja) && sr.equals(raizNueva);
}

async function main() {
  mkdirSync(REG, { recursive: true });
  const salida = { hora: AHORA, sitio: SITIO };
  const problemas = [];
  // 1 · las claves que el sitio publica siguen siendo las guardadas acá
  for (const n of Object.values(LLAVES).map((c) => c[0])) {
    let vivo = null; try { vivo = await bajar('/claves/' + n, true); } catch (e) { vivo = null; }
    if (vivo == null) problemas.push('el sitio no entrega /claves/' + n);
    else if (vivo.trim() !== pem(n).trim()) problemas.push('la clave publicada ' + n + ' NO es la que este testigo guardó');
  }
  salida.clavesIguales = problemas.length === 0;
  // 2 · la última raíz y sus tres sellos
  const j = await bajar('/api/public/registro/raiz');
  const u = j.ultima; if (u == null || u.sth == null || u.sello == null) throw new Error('el sitio no entregó una raíz');
  const canon = Buffer.from(JSON.stringify(u.sth));
  const formato = u.sth.formato === 'FirmaRED-registro-2' ? 2 : 1;
  const s = { ed25519: sello(pem('firmared-sello-ed25519.pem'), canon, u.sello.firma),
    mldsa65: sello(pem('firmared-sello-mldsa65.pem'), canon, u.sello.mldsa65 && u.sello.mldsa65.firma),
    slhdsa: sello(pem('firmared-sello-slhdsa.pem'), canon, u.sello.slhdsa && u.sello.slhdsa.firma) };
  if (formato === 2) {
    s.mldsa87 = sello(pem('firmared-sello-mldsa87.pem'), canon, u.sello.mldsa87 && u.sello.mldsa87.firma);
    s.slhdsa256s = sello(pem('firmared-sello-slhdsa256s.pem'), canon, u.sello.slhdsa256s && u.sello.slhdsa256s.firma);
    // el texto firmado tiene que nombrar las tres claves del sello compuesto, por id y por huella, y decir para qué es
    const nombradas = Array.isArray(u.sth.sellos) ? u.sth.sellos : [];
    for (const k of ['ed25519', 'mldsa87', 'slhdsa256s']) {
      const n = nombradas.find((x) => x && x.clave === IDS[k]);
      if (n == null) problemas.push('el texto firmado de la raíz ' + u.sth.numero + ' no nombra la clave ' + IDS[k]);
      else if (n.huella !== huellaDe(k)) problemas.push('el texto firmado de la raíz ' + u.sth.numero + ' nombra ' + IDS[k] + ' con otra huella');
    }
    if (u.sth.uso !== 'raiz-del-registro') problemas.push('el texto firmado de la raíz ' + u.sth.numero + ' no dice uso raiz-del-registro');
    for (const k of ['ed25519', 'mldsa87', 'slhdsa256s']) if (s[k] !== true) problemas.push('el sello compuesto de la raíz ' + u.sth.numero + ' NO verifica: falta o falla ' + k);
    s.transicion = { mldsa65: s.mldsa65, slhdsa: s.slhdsa }; delete s.mldsa65; delete s.slhdsa;
  } else {
    for (const k of ['ed25519', 'mldsa65', 'slhdsa']) if (s[k] !== true) problemas.push('el sello ' + k + ' de la raíz ' + u.sth.numero + ' NO verifica');
  }
  // el corte: desde esa raíz, todo tiene que estar en formato 2
  let corte = null; try { const e = await bajar('/api/public/registro/estado'); if (e && e.formato2 && e.formato2.corte) corte = Number(e.formato2.corte); } catch (e) { corte = null; }
  const ultPrev = leer(join(REG, 'ultima.json')); if (corte == null && ultPrev && ultPrev.corte) corte = ultPrev.corte;
  if (corte != null && u.sth.numero >= corte && formato !== 2) problemas.push('la raíz ' + u.sth.numero + ' esta en formato 1 despues del corte en la ' + corte);
  Object.assign(salida, { raiz: u.sth.numero, firmas: u.sth.tamano, huella: u.sth.raiz, fecha: u.sth.fecha, bitcoin: u.bitcoin || null, formato, corte, sellos: s });
  // 3 · la raíz nueva contiene a la última que este testigo vio
  const ult = leer(join(REG, 'ultima.json'));
  if (ult && ult.raiz !== undefined) {
    if (ult.raiz === u.sth.numero) { salida.consistencia = ult.huella === u.sth.raiz && ult.firmas === u.sth.tamano ? 'misma raíz que la última vez' : 'LA RAÍZ ' + u.sth.numero + ' CAMBIÓ'; if (salida.consistencia.startsWith('LA')) problemas.push(salida.consistencia); }
    else if (ult.raiz > u.sth.numero) { salida.consistencia = 'EL SITIO VOLVIÓ ATRÁS: tenía la raíz ' + ult.raiz + ' y ahora da la ' + u.sth.numero; problemas.push(salida.consistencia); }
    else {
      const c = await bajar('/api/public/registro/consistencia?de=' + ult.raiz + '&a=' + u.sth.numero);
      const ok = c && c.ok === true && c.de && c.de.raiz === ult.huella && c.de.tamano === ult.firmas && c.a && c.a.raiz === u.sth.raiz &&
        consistencia(ult.firmas, u.sth.tamano, Buffer.from(ult.huella, 'hex'), Buffer.from(u.sth.raiz, 'hex'), (c.prueba || []).map((x) => Buffer.from(x, 'hex')));
      salida.consistencia = ok ? 'la raíz ' + u.sth.numero + ' contiene a la ' + ult.raiz + ' (' + ult.firmas + ' → ' + u.sth.tamano + ' firmas)' : 'LA RAÍZ ' + u.sth.numero + ' NO CONTIENE A LA ' + ult.raiz;
      if (ok !== true) problemas.push(salida.consistencia);
    }
  } else salida.consistencia = 'primera raíz que ve este testigo';
  salida.problemas = problemas; salida.veredicto = problemas.length === 0 ? 'bien' : 'ATENCIÓN';
  // 4 · anotar: una línea por corrida; una por raíz nueva; y el estado para la próxima
  appendFileSync(join(REG, 'corridas.jsonl'), JSON.stringify(salida) + '\n');
  if (problemas.length === 0 && (ult == null || ult.raiz !== u.sth.numero)) {
    appendFileSync(join(REG, 'raices.jsonl'), JSON.stringify({ vista: AHORA, raiz: u.sth.numero, firmas: u.sth.tamano, huella: u.sth.raiz, fecha: u.sth.fecha, formato, sellos: s, bitcoin: u.bitcoin || null }) + '\n');
    writeFileSync(join(REG, 'ultima.json'), JSON.stringify({ vista: AHORA, raiz: u.sth.numero, firmas: u.sth.tamano, huella: u.sth.raiz, fecha: u.sth.fecha, formato, corte }, null, 2) + '\n');
  }
  const vistas = existsSync(join(REG, 'raices.jsonl')) ? readFileSync(join(REG, 'raices.jsonl'), 'utf8').trim().split('\n').filter(Boolean).length : 0;
  const desde = vistas ? JSON.parse(readFileSync(join(REG, 'raices.jsonl'), 'utf8').split('\n')[0]).vista : AHORA;
  writeFileSync(join(AQUI, 'ESTADO.md'), [
    '# Estado del testigo', '',
    'Última mirada: ' + AHORA + ' · veredicto: **' + salida.veredicto + '**', '',
    '- Raíz ' + u.sth.numero + ' · ' + u.sth.tamano + ' firmas · publicada el ' + u.sth.fecha + ' · Bitcoin: ' + (u.bitcoin || 'sin dato'),
    '- Formato ' + formato + (corte != null ? ' · corte al formato 2 en la raíz ' + corte : ' · sin corte todavía'),
    formato === 2
      ? '- Sello compuesto: Ed25519 ' + (s.ed25519 ? 'verifica' : 'NO') + ' · ML-DSA-87 ' + (s.mldsa87 ? 'verifica' : 'NO') + ' · SLH-DSA-SHA2-256s ' + (s.slhdsa256s ? 'verifica' : 'NO') + ' · transición: ML-DSA-65 ' + (s.transicion.mldsa65 ? 'verifica' : 'no viene o no verifica') + ' · SLH-DSA-SHA2-128s ' + (s.transicion.slhdsa ? 'verifica' : 'no viene o no verifica')
      : '- Sellos: Ed25519 ' + (s.ed25519 ? 'verifica' : 'NO') + ' · ML-DSA-65 ' + (s.mldsa65 ? 'verifica' : 'NO') + ' · SLH-DSA-SHA2-128s ' + (s.slhdsa ? 'verifica' : 'NO'),
    '- Consistencia: ' + salida.consistencia,
    '- Claves publicadas por el sitio: ' + (salida.clavesIguales ? 'las mismas que guarda este testigo' : 'DISTINTAS'),
    '- Raíces vistas por este testigo: ' + vistas + ' · desde ' + desde, '',
    ...(problemas.length ? ['## Problemas', '', ...problemas.map((p) => '- ' + p), ''] : []),
    'Cómo se comprueba cada cosa: [LEEME.md](LEEME.md).', ''].join('\n'));
  console.log(JSON.stringify(salida, null, 2));
  if (problemas.length) process.exitCode = 2;
}
main().catch((e) => { console.error('el testigo no pudo mirar: ' + e.message); appendFileSync(join(REG, 'corridas.jsonl'), JSON.stringify({ hora: AHORA, sitio: SITIO, veredicto: 'no pude mirar', error: String(e.message) }) + '\n'); process.exitCode = 3; });
