/**
 * verificar-y-actualizar.js
 * ---------------------------------------------------------------
 * Ejecutado por .github/workflows/actualizar-listas.yml
 *
 * Qué hace, en orden:
 *  1. Lee los issues abiertos con la etiqueta "reporte-dominio" (creados por
 *     el botón "Reportar" del sitio, o abiertos manualmente).
 *  2. Para cada uno, vuelve a verificar el dominio de forma INDEPENDIENTE
 *     contra VirusTotal y urlscan.io — nunca confía solo en lo que dijo el
 *     navegador de quien reportó.
 *  3. Si suficientes motores externos coinciden en que es malicioso, agrega
 *     el dominio a blacklist.txt y regenera dns/rpz-antiphishingrd.txt,
 *     dns/pihole-antiphishingrd.txt y firewall/pfsense-alias.txt.
 *  4. Comenta y cierra el issue si se confirmó; si no, lo deja abierto
 *     marcado para revisión manual y explica por qué no se confirmó.
 *
 * Requiere Node 20+ (usa fetch nativo). No usa dependencias externas.
 */

const fs = require('fs');
const path = require('path');

const CFG = JSON.parse(fs.readFileSync(path.join(__dirname, 'consenso.config.json'), 'utf8'));

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const [OWNER, REPO] = (process.env.GITHUB_REPOSITORY || '').split('/');
const VT_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const URLSCAN_KEY = process.env.URLSCAN_API_KEY || '';
const SOLO_ISSUE = process.env.SOLO_ISSUE_NUMERO || '';

const GH_API = 'https://api.github.com';

// Dominios de proveedores reconocidos que NUNCA se agregan a la blacklist,
// sin importar qué diga VirusTotal/urlscan.io ni quién haya abierto el issue.
// Esta es la última barrera: protege contra un actor malicioso que intente
// reportar un dominio legítimo (google.com, microsoft.com, etc.) para
// sabotearlo y bloquear servicios/operaciones de negocio reales. Cubre el
// dominio y cualquier subdominio. Mantén esta lista igual a TRUSTED_DOMAINS
// en checker.js del sitio.
const TRUSTED_DOMAINS = [
  'google.com', 'youtube.com', 'gmail.com', 'googleapis.com', 'gstatic.com',
  'microsoft.com', 'office.com', 'live.com', 'outlook.com', 'sharepoint.com', 'onedrive.com', 'azure.com',
  'apple.com', 'icloud.com',
  'facebook.com', 'instagram.com', 'whatsapp.com', 'meta.com',
  'amazon.com',
  'cloudflare.com', 'godaddy.com', 'digitalocean.com',
  'dropbox.com', 'box.com', 'slack.com', 'zoom.us', 'webex.com', 'notion.so', 'trello.com', 'asana.com', 'monday.com', 'atlassian.com',
  'github.com', 'gitlab.com', 'bitbucket.org',
  'salesforce.com', 'linkedin.com', 'adobe.com', 'docusign.com', 'paypal.com', 'stripe.com'
];
function esDominioDeConfianza(domain){
  return TRUSTED_DOMAINS.find(d => domain === d || domain.endsWith('.' + d)) || null;
}

// Plataformas de hosting/CDN compartido: si algo malicioso aparece bajo uno
// de estos dominios, nunca se bloquea el dominio completo (rompería el
// servicio para todo el mundo) — solo la URL exacta. Mantén esta lista
// igual a SHARED_HOSTING_DOMAINS en checker.js y server.js.
const SHARED_HOSTING_DOMAINS = [
  'cloudinary.com', 'imgur.com', 'ibb.co', 'postimg.cc',
  'discord.com', 'discordapp.com', 'cdn.discordapp.com', 'media.discordapp.net',
  'telegra.ph', 'pastebin.com',
  'github.io', 'githubusercontent.com',
  'amazonaws.com', 'azurewebsites.net', 'herokuapp.com', 'netlify.app', 'vercel.app', 'firebaseapp.com', 'web.app',
  'blogspot.com', 'weebly.com', 'wixsite.com', 'glitch.me', 'repl.co',
  'ngrok.io', 'ngrok-free.app', 'ngrok.app',
  'dropboxusercontent.com', 'googleusercontent.com'
];
function esHostingCompartido(domain){
  return SHARED_HOSTING_DOMAINS.find(d => domain === d || domain.endsWith('.' + d)) || null;
}

function ghHeaders(){
  return {
    'Authorization': `Bearer ${GITHUB_TOKEN}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28'
  };
}

async function listaDeIssuesReportados(){
  if(SOLO_ISSUE){
    const r = await fetch(`${GH_API}/repos/${OWNER}/${REPO}/issues/${SOLO_ISSUE}`, {headers: ghHeaders()});
    if(!r.ok) return [];
    const issue = await r.json();
    return issue.state === 'open' ? [issue] : [];
  }
  const r = await fetch(`${GH_API}/repos/${OWNER}/${REPO}/issues?labels=reporte-dominio&state=open&per_page=50`, {headers: ghHeaders()});
  if(!r.ok) return [];
  return r.json();
}

async function comentarIssue(numero, cuerpo){
  await fetch(`${GH_API}/repos/${OWNER}/${REPO}/issues/${numero}/comments`, {
    method:'POST', headers: ghHeaders(), body: JSON.stringify({body: cuerpo})
  });
}

async function actualizarIssue(numero, cambios){
  await fetch(`${GH_API}/repos/${OWNER}/${REPO}/issues/${numero}`, {
    method:'PATCH', headers: ghHeaders(), body: JSON.stringify(cambios)
  });
}

function extraerDominio(body){
  const m = /Dominio:\s*([^\s]+)/i.exec(body || '');
  if(!m) return null;
  return m[1].trim().toLowerCase().replace(/[.,;]+$/,'');
}

function extraerUrlCompleta(body){
  const m = /URL analizada:\s*([^\s]+)/i.exec(body || '');
  return m ? m[1].trim() : null;
}

function esSoloUrl(body){
  return /Alcance del bloqueo:\s*solo-url/i.test(body || '');
}

// ---------------- VirusTotal ----------------
async function consultarVirusTotal(domain){
  if(!VT_KEY) return {disponible:false};
  try{
    const r = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
      headers:{'x-apikey': VT_KEY}
    });
    if(!r.ok) return {disponible:false};
    const data = await r.json();
    const stats = (data.data && data.data.attributes && data.data.attributes.last_analysis_stats) || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a,b) => a + (Number(b)||0), 0) || 1;
    return {disponible:true, malicious, suspicious, total, flagged: malicious >= CFG.virusTotal.minMotoresMaliciosos};
  }catch(e){ return {disponible:false}; }
}

// ---------------- urlscan.io ----------------
async function buscarUrlscanExistente(domain){
  try{
    const headers = URLSCAN_KEY ? {'API-Key': URLSCAN_KEY} : {};
    const r = await fetch(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=5`, {headers});
    if(!r.ok) return null;
    const data = await r.json();
    if(!data.results || !data.results.length) return null;
    const conVeredicto = data.results.find(x => x.verdicts && typeof x.verdicts.overall !== 'undefined');
    return conVeredicto || data.results[0];
  }catch(e){ return null; }
}

async function enviarNuevoUrlscan(domain, urlCompleta){
  if(!URLSCAN_KEY) return null;
  try{
    const submit = await fetch('https://urlscan.io/api/v1/scan/', {
      method:'POST',
      headers:{'API-Key': URLSCAN_KEY, 'Content-Type':'application/json'},
      body: JSON.stringify({url: urlCompleta || `http://${domain}`, visibility:'public'})
    });
    if(!submit.ok) return null;
    const { api } = await submit.json();
    if(!api) return null;
    // urlscan.io tarda ~10-20s en procesar; reintenta unas pocas veces.
    for(let i=0;i<6;i++){
      await new Promise(res => setTimeout(res, 8000));
      const r = await fetch(api, {headers:{'API-Key': URLSCAN_KEY}});
      if(r.ok) return r.json();
    }
    return null;
  }catch(e){ return null; }
}

async function consultarUrlscan(domain, urlCompleta){
  // Si tenemos la URL exacta (caso de hosting compartido), no reutilizamos
  // un escaneo viejo del dominio en general — puede haber evaluado otra
  // página distinta del mismo sitio. Vamos directo a escanear esa URL.
  let resultado = urlCompleta ? null : await buscarUrlscanExistente(domain);
  if(!resultado) resultado = await enviarNuevoUrlscan(domain, urlCompleta);
  if(!resultado) return {disponible:false};
  const overall = resultado.verdicts && resultado.verdicts.overall;
  if(!overall) return {disponible:false};
  return {disponible:true, malicious: !!overall.malicious, score: overall.score || 0, flagged: !!overall.malicious};
}

// ---------------- listas derivadas ----------------
function leerLista(nombreArchivo){
  try{
    return fs.readFileSync(nombreArchivo, 'utf8').split('\n').map(l => l.trim()).filter(Boolean);
  }catch(e){ return []; }
}

function asegurarCarpeta(nombreArchivo){
  const dir = path.dirname(nombreArchivo);
  if(dir && dir !== '.') fs.mkdirSync(dir, {recursive:true});
}

function regenerarListasDerivadas(dominios, urlsCompletas){
  // Filtro de seguridad final: aunque un dominio de confianza se haya
  // colado a la lista por cualquier otra vía, nunca se escribe a los
  // archivos publicados.
  const sinProtegidos = dominios.filter(d => !esDominioDeConfianza(d));
  const excluidos = dominios.filter(d => esDominioDeConfianza(d));
  if(excluidos.length){
    console.log(`Excluidos por ser dominios de confianza (no se publican): ${excluidos.join(', ')}`);
  }
  const ordenados = [...new Set(sinProtegidos)].sort();
  const fecha = new Date().toISOString();

  // ---- Fuente principal: un dominio por línea ----
  // También sirve tal cual como feed para FortiGate (Threat Feeds > Domain
  // Name), Palo Alto (External Dynamic List de dominios), Cisco Umbrella
  // (Custom Destination List) y NextDNS (Denylist): las cuatro aceptan una
  // URL con un dominio por línea, sin ningún formato especial.
  asegurarCarpeta(CFG.archivos.blacklist);
  fs.writeFileSync(CFG.archivos.blacklist, ordenados.join('\n') + '\n');

  // ---- BIND / Windows Server DNS (zona RPZ) ----
  asegurarCarpeta(CFG.archivos.dnsRpz);
  const rpz = [
    `$TTL 300`,
    `@ SOA localhost. admin.localhost. (${Math.floor(Date.now()/1000)} 3600 600 86400 300)`,
    `  NS  localhost.`,
    `; Zona RPZ generada automaticamente por AntiPhishingRD (${fecha}). No editar a mano.`,
    ...ordenados.map(d => `${d} CNAME .`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.dnsRpz, rpz);

  // ---- Unbound nativo (sin módulo RPZ) ----
  asegurarCarpeta(CFG.archivos.unbound);
  const unbound = [
    `# Bloqueo nativo para Unbound (sin módulo RPZ). Generado por AntiPhishingRD (${fecha}).`,
    `# Inclúyelo en unbound.conf con: include: "/ruta/a/este/archivo"`,
    ...ordenados.map(d => `local-zone: "${d}." always_nxdomain`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.unbound, unbound);

  // ---- Pi-hole (formato hosts) ----
  asegurarCarpeta(CFG.archivos.pihole);
  const pihole = [
    `# Lista Pi-hole (formato hosts). Generado por AntiPhishingRD (${fecha}).`,
    ...ordenados.map(d => `0.0.0.0 ${d}`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.pihole, pihole);

  // ---- AdGuard Home (sintaxis adblock nativa) ----
  asegurarCarpeta(CFG.archivos.adguard);
  const adguard = [
    `! Lista AdGuard Home (sintaxis adblock). Generado por AntiPhishingRD (${fecha}).`,
    `! Agregar en Filtros > Listas de bloqueo DNS > Agregar lista de bloqueo personalizada`,
    ...ordenados.map(d => `||${d}^`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.adguard, adguard);

  // ---- dnsmasq ----
  asegurarCarpeta(CFG.archivos.dnsmasq);
  const dnsmasq = [
    `# Bloqueo para dnsmasq. Generado por AntiPhishingRD (${fecha}).`,
    `# Inclúyelo con: conf-file=/ruta/a/este/archivo (o colócalo en /etc/dnsmasq.d/)`,
    ...ordenados.map(d => `address=/${d}/0.0.0.0`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.dnsmasq, dnsmasq);

  // ---- pfSense / OPNsense / pfBlockerNG (lista simple para feed personalizado) ----
  asegurarCarpeta(CFG.archivos.firewall);
  const fw = [
    `# Feed de dominios bloqueados para pfSense (pfBlockerNG DNSBL) y OPNsense`,
    `# (bloqueador de dominios de Unbound). Generado por AntiPhishingRD (${fecha}).`,
    ...ordenados,
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.firewall, fw);

  // ---- MikroTik RouterOS (script listo para importar) ----
  asegurarCarpeta(CFG.archivos.mikrotik);
  const mikrotik = [
    `# Script RouterOS. Generado por AntiPhishingRD (${fecha}).`,
    `# Importar con: /import file-name=mikrotik-antiphishingrd.rsc`,
    `/ip dns static`,
    ...ordenados.map(d => `add name=${d} type=A address=0.0.0.0 comment="AntiPhishingRD"`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.mikrotik, mikrotik);

  // ---- Squid proxy (ACL dstdomain) ----
  asegurarCarpeta(CFG.archivos.squid);
  const squid = [
    `# ACL dstdomain para Squid. Generado por AntiPhishingRD (${fecha}).`,
    `# En squid.conf: acl antiphishingrd dstdomain "/ruta/a/este/archivo"`,
    `#                http_access deny antiphishingrd`,
    ...ordenados.map(d => `.${d}`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.squid, squid);

  // ---- URLs completas (hosting compartido: NUNCA se bloquea el dominio) ----
  // El DNS no puede filtrar por ruta, solo por dominio — por eso estas URLs
  // no aparecen en ninguno de los archivos de arriba. Sirven para un proxy
  // con soporte de URL completa (Squid con url_regex, un WAF, o una
  // extensión de navegador con lista de bloqueo), nunca para DNS/firewall.
  if(CFG.archivos.blacklistUrls){
    const urlsOrdenadas = [...new Set(urlsCompletas || [])].sort();
    asegurarCarpeta(CFG.archivos.blacklistUrls);
    const urlsTxt = [
      `# URLs exactas confirmadas como maliciosas en plataformas de hosting`,
      `# compartido (no se bloquea el dominio completo). Generado por`,
      `# AntiPhishingRD (${fecha}). Una URL por línea.`,
      ...urlsOrdenadas,
      ''
    ].join('\n');
    fs.writeFileSync(CFG.archivos.blacklistUrls, urlsTxt);
  }
}

// ---------------- proceso principal ----------------
async function main(){
  if(!GITHUB_TOKEN || !OWNER || !REPO){
    console.log('Faltan credenciales de GitHub en el entorno — nada que hacer.');
    return;
  }

  const dominiosActuales = leerLista(CFG.archivos.blacklist);
  const setActual = new Set(dominiosActuales);
  const urlsActuales = new Set(CFG.archivos.blacklistUrls ? leerLista(CFG.archivos.blacklistUrls) : []);
  let huboCambios = false;
  let huboCambiosUrls = false;

  const issues = await listaDeIssuesReportados();
  console.log(`Issues de reporte a procesar: ${issues.length}`);

  for(const issue of issues){
    const domain = extraerDominio(issue.body);
    if(!domain){
      await comentarIssue(issue.number, 'No se pudo identificar el dominio en este reporte. Edítalo con el formato "Dominio: ejemplo.com" o ciérralo manualmente.');
      continue;
    }

    const proveedor = esDominioDeConfianza(domain);
    if(proveedor){
      await comentarIssue(issue.number, [
        `🛡️ **Dominio protegido, no se procesa.** \`${domain}\` pertenece a ${proveedor}, un proveedor reconocido en la lista de exclusión.`,
        '',
        'Este dominio nunca se agrega a la blacklist automáticamente, sin importar el resultado de los motores externos — esto protege contra reportes maliciosos que busquen bloquear un servicio legítimo. Si de verdad detectaste phishing alojado bajo este proveedor (por ejemplo, una página fraudulenta en un subdominio de hosting gratuito), repórtalo directamente al proveedor además de aquí.'
      ].join('\n'));
      await actualizarIssue(issue.number, {state:'closed', labels:['reporte-dominio','dominio-protegido']});
      continue;
    }

    const soloUrl = esSoloUrl(issue.body) || !!esHostingCompartido(domain);
    const urlCompleta = extraerUrlCompleta(issue.body);

    // ---- Caso: hosting compartido, solo se bloquea la URL exacta ----
    if(soloUrl){
      if(!urlCompleta){
        await comentarIssue(issue.number, `\`${domain}\` es una plataforma de hosting compartido, pero no se pudo leer la URL exacta en este reporte. Edítalo con el formato "URL analizada: https://..." o ciérralo manualmente.`);
        continue;
      }
      if(urlsActuales.has(urlCompleta)){
        await comentarIssue(issue.number, `La URL \`${urlCompleta}\` ya está publicada en la lista de URLs exactas — no se requiere ninguna acción adicional. El dominio \`${domain}\` en sí nunca se bloquea, por ser hosting compartido.`);
        await actualizarIssue(issue.number, {state:'closed', labels:['reporte-dominio','ya-publicado','solo-url']});
        continue;
      }

      console.log(`Verificando URL exacta ${urlCompleta} (dominio de hosting compartido: ${domain})…`);
      const urlscan = await consultarUrlscan(domain, urlCompleta);
      const motoresConsultados = [];
      let motoresDeAcuerdo = 0;
      if(urlscan.disponible){ motoresConsultados.push(`urlscan.io sobre la URL exacta: veredicto ${urlscan.malicious ? 'MALICIOSO' : 'sin indicios'} (score ${urlscan.score}).`); if(urlscan.flagged) motoresDeAcuerdo++; }

      const seConfirma = motoresDeAcuerdo >= CFG.minMotoresExternosDeAcuerdo && urlscan.disponible;

      if(seConfirma){
        urlsActuales.add(urlCompleta);
        huboCambiosUrls = true;
        await comentarIssue(issue.number, [
          `✅ **Confirmado de forma independiente.** Se agrega la URL exacta \`${urlCompleta}\` a la lista de URLs bloqueadas.`,
          '',
          `⚠️ El dominio \`${domain}\` **no** se agrega a ningún archivo de DNS/firewall — es una plataforma de hosting compartido, y bloquear el dominio completo rompería el servicio para todos los demás usuarios. La URL exacta solo sirve para proxies con soporte de URL completa (Squid con url_regex) o extensiones de navegador, no para DNS.`,
          '',
          ...motoresConsultados
        ].join('\n'));
        await actualizarIssue(issue.number, {state:'closed', labels:['reporte-dominio','confirmado','solo-url']});
      }else{
        const motivo = urlscan.disponible
          ? 'urlscan.io no confirmó esta URL específica como maliciosa.'
          : 'No hay clave de urlscan.io configurada como secret del repositorio (URLSCAN_API_KEY), o el escaneo de esta URL exacta falló — no se puede verificar de forma automática todavía.';
        await comentarIssue(issue.number, [
          `⏳ **No se confirma automáticamente todavía.** ${motivo}`,
          '',
          ...(motoresConsultados.length ? motoresConsultados : ['Ningún motor externo respondió sobre esta URL exacta.']),
          '',
          'Este reporte queda abierto para revisión manual.'
        ].join('\n'));
        await actualizarIssue(issue.number, {labels:['reporte-dominio','revision-manual','solo-url']});
      }
      continue;
    }

    // ---- Caso normal: se puede bloquear el dominio completo ----
    if(setActual.has(domain)){
      await comentarIssue(issue.number, `El dominio \`${domain}\` ya está publicado en la blacklist — no se requiere ninguna acción adicional.`);
      await actualizarIssue(issue.number, {state:'closed', labels:['reporte-dominio','ya-publicado']});
      continue;
    }

    console.log(`Verificando ${domain}…`);
    const [vt, urlscan] = await Promise.all([consultarVirusTotal(domain), consultarUrlscan(domain)]);

    const motoresConsultados = [];
    let motoresDeAcuerdo = 0;
    if(vt.disponible){ motoresConsultados.push(`VirusTotal: ${vt.malicious}/${vt.total} motores lo marcan malicioso.`); if(vt.flagged) motoresDeAcuerdo++; }
    if(urlscan.disponible){ motoresConsultados.push(`urlscan.io: veredicto ${urlscan.malicious ? 'MALICIOSO' : 'sin indicios'} (score ${urlscan.score}).`); if(urlscan.flagged) motoresDeAcuerdo++; }

    const seConfirma = motoresDeAcuerdo >= CFG.minMotoresExternosDeAcuerdo && (vt.disponible || urlscan.disponible);

    if(seConfirma){
      setActual.add(domain);
      huboCambios = true;
      await comentarIssue(issue.number, [
        `✅ **Confirmado de forma independiente** — se agrega \`${domain}\` a la blacklist pública, la zona DNS RPZ, la lista de Pi-hole y el alias de firewall.`,
        '',
        ...motoresConsultados
      ].join('\n'));
      await actualizarIssue(issue.number, {state:'closed', labels:['reporte-dominio','confirmado']});
    }else{
      const motivo = (vt.disponible || urlscan.disponible)
        ? 'Los motores externos consultados no alcanzaron el consenso mínimo para confirmarlo automáticamente.'
        : 'No hay claves de VirusTotal/urlscan.io configuradas como secrets del repositorio (VIRUSTOTAL_API_KEY / URLSCAN_API_KEY) — no se puede verificar de forma automática todavía.';
      await comentarIssue(issue.number, [
        `⏳ **No se confirma automáticamente todavía.** ${motivo}`,
        '',
        ...(motoresConsultados.length ? motoresConsultados : ['Ningún motor externo respondió.']),
        '',
        'Este reporte queda abierto para revisión manual. Si un analista confirma que es malicioso, agrégalo a mano a blacklist.txt o vuelve a etiquetar el issue una vez configuradas las claves de los motores externos.'
      ].join('\n'));
      await actualizarIssue(issue.number, {labels:['reporte-dominio','revision-manual']});
    }
  }

  if(huboCambios || huboCambiosUrls){
    regenerarListasDerivadas([...setActual], [...urlsActuales]);
    console.log('Listas regeneradas con los nuevos dominios/URLs confirmados.');
  }else{
    console.log('Ningún dominio ni URL nuevo fue confirmado en esta pasada.');
  }
}

main().catch(err => { console.error(err); process.exit(1); });
