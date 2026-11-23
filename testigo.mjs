// Testigo externo del registro público de FirmaRED.
// Cada vez que corre: baja la última raíz del registro, comprueba sus tres sellos (Ed25519, ML-DSA-65 y SLH-DSA-SHA2-128s) con
// las claves públicas guardadas en este repositorio, comprueba que la raíz nueva contenga a la anterior que este testigo ya vio
// (prueba de consistencia RFC 9162), comprueba que las claves que el sitio publica sigan siendo las guardadas, y anota el
// veredicto en registro/. No usa ninguna biblioteca: solo el OpenSSL que trae Node 24 o posterior. No firma nada; solo lee.
//   node testigo.mjs            corre una vez
//   node testigo.mjs --sitio https://otro   otra dirección del sitio
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const AQUI = dirname(fileURLToPath(import.meta.url));
const SITIO = (process.argv.indexOf('--sitio') > 0 ? process.argv[process.argv.indexOf('--sitio') + 1] : 'https://firmared.com').replace(/\/$/, '');
const CLAVES = join(AQUI, 'claves'), REG = join(AQUI, 'registro');
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
  for (const n of ['firmared-sello-ed25519.pem', 'firmared-sello-mldsa65.pem', 'firmared-sello-slhdsa.pem']) {
    let vivo = null; try { vivo = await bajar('/claves/' + n, true); } catch (e) { vivo = null; }
    if (vivo == null) problemas.push('el sitio no entrega /claves/' + n);
    else if (vivo.trim() !== pem(n).trim()) problemas.push('la clave publicada ' + n + ' NO es la que este testigo guardó');
  }
  salida.clavesIguales = problemas.length === 0;
  // 2 · la última raíz y sus tres sellos
  const j = await bajar('/api/public/registro/raiz');
  const u = j.ultima; if (u == null || u.sth == null || u.sello == null) throw new Error('el sitio no entregó una raíz');
  const canon = Buffer.from(JSON.stringify(u.sth));
  const s = { ed25519: sello(pem('firmared-sello-ed25519.pem'), canon, u.sello.firma),
    mldsa65: sello(pem('firmared-sello-mldsa65.pem'), canon, u.sello.mldsa65 && u.sello.mldsa65.firma),
    slhdsa: sello(pem('firmared-sello-slhdsa.pem'), canon, u.sello.slhdsa && u.sello.slhdsa.firma) };
  Object.assign(salida, { raiz: u.sth.numero, firmas: u.sth.tamano, huella: u.sth.raiz, fecha: u.sth.fecha, bitcoin: u.bitcoin || null, sellos: s });
  for (const k of Object.keys(s)) if (s[k] !== true) problemas.push('el sello ' + k + ' de la raíz ' + u.sth.numero + ' NO verifica');
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
    appendFileSync(join(REG, 'raices.jsonl'), JSON.stringify({ vista: AHORA, raiz: u.sth.numero, firmas: u.sth.tamano, huella: u.sth.raiz, fecha: u.sth.fecha, sellos: s, bitcoin: u.bitcoin || null }) + '\n');
    writeFileSync(join(REG, 'ultima.json'), JSON.stringify({ vista: AHORA, raiz: u.sth.numero, firmas: u.sth.tamano, huella: u.sth.raiz, fecha: u.sth.fecha }, null, 2) + '\n');
  }
  const vistas = existsSync(join(REG, 'raices.jsonl')) ? readFileSync(join(REG, 'raices.jsonl'), 'utf8').trim().split('\n').filter(Boolean).length : 0;
  const desde = vistas ? JSON.parse(readFileSync(join(REG, 'raices.jsonl'), 'utf8').split('\n')[0]).vista : AHORA;
  writeFileSync(join(AQUI, 'ESTADO.md'), [
    '# Estado del testigo', '',
    'Última mirada: ' + AHORA + ' · veredicto: **' + salida.veredicto + '**', '',
    '- Raíz ' + u.sth.numero + ' · ' + u.sth.tamano + ' firmas · publicada el ' + u.sth.fecha + ' · Bitcoin: ' + (u.bitcoin || 'sin dato'),
    '- Sellos: Ed25519 ' + (s.ed25519 ? 'verifica' : 'NO') + ' · ML-DSA-65 ' + (s.mldsa65 ? 'verifica' : 'NO') + ' · SLH-DSA-SHA2-128s ' + (s.slhdsa ? 'verifica' : 'NO'),
    '- Consistencia: ' + salida.consistencia,
    '- Claves publicadas por el sitio: ' + (salida.clavesIguales ? 'las mismas que guarda este testigo' : 'DISTINTAS'),
    '- Raíces vistas por este testigo: ' + vistas + ' · desde ' + desde, '',
    ...(problemas.length ? ['## Problemas', '', ...problemas.map((p) => '- ' + p), ''] : []),
    'Cómo se comprueba cada cosa: [LEEME.md](LEEME.md).', ''].join('\n'));
  console.log(JSON.stringify(salida, null, 2));
  if (problemas.length) process.exitCode = 2;
}
main().catch((e) => { console.error('el testigo no pudo mirar: ' + e.message); appendFileSync(join(REG, 'corridas.jsonl'), JSON.stringify({ hora: AHORA, sitio: SITIO, veredicto: 'no pude mirar', error: String(e.message) }) + '\n'); process.exitCode = 3; });
