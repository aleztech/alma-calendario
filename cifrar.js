#!/usr/bin/env node
/**
 * Genera el index.html publicado a partir de fuente/calendario.html.
 *
 * El HTML resultante solo contiene datos cifrados con AES-256-GCM.
 * Sin la contraseña no hay nada legible, ni siquiera viendo el codigo fuente.
 *
 *   node cifrar.js              -> pide las dos contrasenas y genera index.html
 *   node cifrar.js --extraer    -> recupera fuente/calendario.html desde index.html
 *
 * Las contrasenas no se guardan en ningun fichero.
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const RAIZ = __dirname;
const FUENTE = path.join(RAIZ, 'fuente', 'calendario.html');
const SALIDA = path.join(RAIZ, 'index.html');

const ITER = 310000;          // PBKDF2-SHA256, recomendacion OWASP
const LONG_CLAVE = 32;        // AES-256
const LONG_SAL = 16;
const LONG_IV = 12;

// ─────────────────────────── utilidades ───────────────────────────

function preguntar(texto, oculto) {
  return new Promise(resolve => {
    process.stdout.write(texto);
    const stdin = process.stdin;
    stdin.resume();
    stdin.setEncoding('utf8');
    if (oculto && stdin.isTTY) stdin.setRawMode(true);
    let valor = '';
    const onData = ch => {
      for (const c of ch) {
        if (c === '\n' || c === '\r' || c === '\u0004') {
          if (oculto && stdin.isTTY) stdin.setRawMode(false);
          stdin.removeListener('data', onData);
          stdin.pause();
          process.stdout.write('\n');
          return resolve(valor);
        }
        if (c === '\u0003') { process.exit(1); }
        if (c === '\u007f') { valor = valor.slice(0, -1); continue; }
        valor += c;
      }
    };
    stdin.on('data', onData);
  });
}

function derivar(contrasena, sal) {
  return crypto.pbkdf2Sync(contrasena, sal, ITER, LONG_CLAVE, 'sha256');
}

function cifrar(textoPlano, contrasena) {
  const sal = crypto.randomBytes(LONG_SAL);
  const iv = crypto.randomBytes(LONG_IV);
  const clave = derivar(contrasena, sal);
  const c = crypto.createCipheriv('aes-256-gcm', clave, iv);
  const datos = Buffer.concat([c.update(textoPlano, 'utf8'), c.final()]);
  return Buffer.concat([sal, iv, datos, c.getAuthTag()]).toString('base64');
}

function descifrar(blobB64, contrasena) {
  const b = Buffer.from(blobB64, 'base64');
  const sal = b.subarray(0, LONG_SAL);
  const iv = b.subarray(LONG_SAL, LONG_SAL + LONG_IV);
  const tag = b.subarray(b.length - 16);
  const datos = b.subarray(LONG_SAL + LONG_IV, b.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', derivar(contrasena, sal), iv);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(datos), d.final()]).toString('utf8');
}

// ────────────────────── lectura de la fuente ──────────────────────

function trocear(texto, etiqueta) {
  const ini = texto.indexOf('<' + etiqueta + '>');
  const fin = texto.indexOf('</' + etiqueta + '>', ini);
  if (ini < 0 || fin < 0) throw new Error('No encuentro el bloque <' + etiqueta + '> en la fuente');
  return texto.slice(ini + etiqueta.length + 2, fin).trim();
}

/** Quita los tramos marcados como privados (lo que la madre no debe ver). */
function quitarPrivado(texto) {
  return texto
    .replace(/<!--\s*<<<PRIVADO\s*-->[\s\S]*?<!--\s*PRIVADO>>>\s*-->/g, '')
    .replace(/\/\*\s*<<<PRIVADO\s*\*\/[\s\S]*?\/\*\s*PRIVADO>>>\s*\*\//g, '')
    .replace(/\/\/\s*<<<PRIVADO[\s\S]*?\/\/\s*PRIVADO>>>/g, '')
    .trim();
}

/** Deja el contenido tal cual, solo borrando las lineas marcadoras. */
function limpiarMarcas(texto) {
  return texto
    .replace(/<!--\s*<<<PRIVADO\s*-->\n?/g, '')
    .replace(/<!--\s*PRIVADO>>>\s*-->\n?/g, '')
    .replace(/\/\*\s*<<<PRIVADO\s*\*\/\n?/g, '')
    .replace(/\/\*\s*PRIVADO>>>\s*\*\/\n?/g, '')
    .replace(/\/\/\s*<<<PRIVADO\n?/g, '')
    .replace(/\/\/\s*PRIVADO>>>\n?/g, '')
    .trim();
}

// ──────────────────────── plantilla publica ───────────────────────

function plantilla(blobCompleto, blobCalendario) {
  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow, noarchive">
<title>Calendario privado</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Serif+Display&display=swap');
*{box-sizing:border-box;margin:0;padding:0;}
html,body{overflow-x:hidden;max-width:100%;}
body{font-family:'DM Sans',sans-serif;background:#f8fafc;color:#0f172a;}
#acceso{position:fixed;inset:0;background:#f8fafc;display:flex;align-items:center;justify-content:center;z-index:9999;padding:20px;}
#caja{background:#fff;border:1px solid #e2e8f0;border-radius:20px;padding:40px 36px;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.1);max-width:360px;width:100%;}
#caja .candado{font-size:48px;margin-bottom:16px;}
#caja h1{font-family:'DM Serif Display',serif;font-size:22px;color:#0f172a;margin-bottom:6px;font-weight:400;}
#caja p{font-size:13px;color:#64748b;margin-bottom:24px;}
#clave{width:100%;padding:12px 16px;border:2px solid #e2e8f0;border-radius:10px;font-size:15px;font-family:'DM Sans',sans-serif;outline:none;text-align:center;letter-spacing:2px;transition:border .2s;}
#clave:focus{border-color:#6366f1;}
#entrar{margin-top:12px;width:100%;padding:12px;background:#1e293b;color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:700;font-family:'DM Sans',sans-serif;cursor:pointer;letter-spacing:.5px;transition:background .2s;}
#entrar:hover{background:#334155;}
#entrar:disabled{opacity:.6;cursor:default;}
#aviso{color:#ef4444;font-size:12px;margin-top:10px;min-height:16px;}
#contenido{display:none;padding:28px 16px 60px;}
</style>
</head>
<body>

<div id="acceso">
  <div id="caja">
    <div class="candado">&#128274;</div>
    <h1>Calendario privado</h1>
    <p>Introduce la contrase&ntilde;a para continuar</p>
    <input id="clave" type="password" placeholder="&middot;&middot;&middot;&middot;&middot;&middot;&middot;&middot;&middot;&middot;&middot;&middot;" autofocus autocomplete="current-password"/>
    <button id="entrar">Entrar</button>
    <div id="aviso"></div>
  </div>
</div>

<div id="contenido"></div>

<script>
// Los datos viajan cifrados con AES-256-GCM. La clave se deriva de la contrasena
// con PBKDF2-SHA256 (${ITER} iteraciones). Sin contrasena esto es ruido.
const BLOBS=[
  ${JSON.stringify(blobCompleto)},
  ${JSON.stringify(blobCalendario)}
];
const ITER=${ITER};

const $=id=>document.getElementById(id);
const b64=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));

async function abrir(blob,contrasena){
  const raw=b64(blob);
  const sal=raw.slice(0,${LONG_SAL});
  const iv=raw.slice(${LONG_SAL},${LONG_SAL + LONG_IV});
  const cuerpo=raw.slice(${LONG_SAL + LONG_IV});
  const base=await crypto.subtle.importKey('raw',new TextEncoder().encode(contrasena),'PBKDF2',false,['deriveKey']);
  const clave=await crypto.subtle.deriveKey(
    {name:'PBKDF2',salt:sal,iterations:ITER,hash:'SHA-256'},
    base,{name:'AES-GCM',length:256},false,['decrypt']);
  const claro=await crypto.subtle.decrypt({name:'AES-GCM',iv:iv},clave,cuerpo);
  return JSON.parse(new TextDecoder().decode(claro));
}

function pintar(datos){
  const estilo=document.createElement('style');
  estilo.textContent=datos.css;
  document.head.appendChild(estilo);
  const caja=$('contenido');
  caja.innerHTML='<div class="page">'+datos.markup+'</div>';
  $('acceso').remove();
  caja.style.display='block';
  try{ new Function(datos.js)(); }
  catch(e){ console.error(e); caja.innerHTML='<p style="padding:40px;text-align:center">Error al montar el calendario.</p>'; }
}

async function intentar(){
  const contrasena=$('clave').value;
  if(!contrasena) return;
  if(!window.crypto||!crypto.subtle){
    $('aviso').textContent='Abre la pagina por https, no como fichero local.';
    return;
  }
  $('entrar').disabled=true;
  $('aviso').textContent='Descifrando\\u2026';
  await new Promise(r=>setTimeout(r,30));
  for(const blob of BLOBS){
    try{ return pintar(await abrir(blob,contrasena)); }catch(e){}
  }
  $('entrar').disabled=false;
  $('aviso').textContent='Contrase\\u00f1a incorrecta';
  $('clave').value='';
  $('clave').focus();
}

$('entrar').addEventListener('click',intentar);
$('clave').addEventListener('keydown',e=>{if(e.key==='Enter')intentar();});
</script>
</body>
</html>
`;
}

// ──────────────────────────── acciones ────────────────────────────

/**
 * Comprueba que ninguna palabra sensible ha quedado en claro en index.html.
 * La lista vive en fuente/palabras-prohibidas.txt, que no se sube a GitHub.
 */
function verificar() {
  const lista = path.join(RAIZ, 'fuente', 'palabras-prohibidas.txt');
  if (!fs.existsSync(lista)) {
    console.log('\n(sin fuente/palabras-prohibidas.txt: me salto la verificacion)');
    return true;
  }
  const publicado = fs.readFileSync(SALIDA, 'utf8').toLowerCase();
  const fugas = fs.readFileSync(lista, 'utf8')
    .split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'))
    .filter(palabra => publicado.includes(palabra.toLowerCase()));
  if (fugas.length) {
    console.error('\nPELIGRO: esto ha quedado LEGIBLE en index.html:');
    fugas.forEach(f => console.error('   - ' + f));
    console.error('NO subas el fichero.\n');
    return false;
  }
  console.log('Verificado: nada legible en la pagina publicada.');
  return true;
}

async function construir() {
  const fuente = fs.readFileSync(FUENTE, 'utf8');
  const css = trocear(fuente, 'style');
  const markup = trocear(fuente, 'markup');
  const js = trocear(fuente, 'script');

  console.log('\nContrasenas nuevas (no se guardan en ningun sitio).');
  console.log('Usa frases largas. Cuanto mas corta, mas facil de romper por fuerza bruta.\n');
  const clavePapa = await preguntar('  Tu contrasena (lo ves todo)      : ', true);
  const claveMadre = await preguntar('  Contrasena de la madre (calendario): ', true);

  if (!clavePapa || !claveMadre) { console.error('\nContrasena vacia. Cancelado.'); process.exit(1); }
  if (clavePapa === claveMadre) { console.error('\nTienen que ser distintas. Cancelado.'); process.exit(1); }
  for (const [nombre, c] of [['tuya', clavePapa], ['de la madre', claveMadre]]) {
    if (c.length < 10) { console.error('\nLa contrasena ' + nombre + ' tiene menos de 10 caracteres. Cancelado.'); process.exit(1); }
  }

  const completo = { css: limpiarMarcas(css), markup: limpiarMarcas(markup), js: limpiarMarcas(js) };
  const soloCalendario = { css: limpiarMarcas(css), markup: quitarPrivado(markup), js: quitarPrivado(js) };

  fs.writeFileSync(SALIDA, plantilla(
    cifrar(JSON.stringify(completo), clavePapa),
    cifrar(JSON.stringify(soloCalendario), claveMadre)
  ));

  console.log('\nindex.html generado (' + Math.round(fs.statSync(SALIDA).size / 1024) + ' KB).');
  if (!verificar()) process.exit(1);
  console.log('Ya puedes subirlo:  git add -A && git commit -m "calendario" && git push\n');
}

async function extraer() {
  const html = fs.readFileSync(SALIDA, 'utf8');
  const blobs = [...html.matchAll(/"([A-Za-z0-9+/=]{500,})"/g)].map(m => m[1]);
  if (!blobs.length) { console.error('No encuentro datos cifrados en index.html'); process.exit(1); }
  const contrasena = await preguntar('\n  Tu contrasena: ', true);
  for (const b of blobs) {
    try {
      const d = JSON.parse(descifrar(b, contrasena));
      if (!d.markup.includes('milestones')) continue;   // esa es la version recortada
      fs.mkdirSync(path.dirname(FUENTE), { recursive: true });
      fs.writeFileSync(FUENTE,
        '<style>\n' + d.css + '\n</style>\n\n<markup>\n' + d.markup + '\n</markup>\n\n<script>\n' + d.js + '\n</script>\n');
      console.log('\nfuente/calendario.html recuperado.');
      console.log('OJO: los marcadores <<<PRIVADO se pierden al extraer, vuelve a ponerlos antes de cifrar.\n');
      return;
    } catch (e) { }
  }
  console.error('\nContrasena incorrecta.\n');
  process.exit(1);
}

module.exports = { cifrar, descifrar, plantilla, trocear, limpiarMarcas, quitarPrivado, FUENTE, SALIDA };

if (require.main === module) {
  (process.argv.includes('--extraer') ? extraer() : construir()).catch(e => {
    console.error('\n' + e.message + '\n');
    process.exit(1);
  });
}
