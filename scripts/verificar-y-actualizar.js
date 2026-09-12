const fs = require('fs');
const path = require('path');

const CFG = JSON.parse(fs.readFileSync(path.join(__dirname, 'consenso.config.json'), 'utf8'));

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const [OWNER, REPO] = (process.env.GITHUB_REPOSITORY || '').split('/');
const VT_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const URLSCAN_KEY = process.env.URLSCAN_API_KEY || '';
const URLHAUS_KEY = process.env.URLHAUS_AUTH_KEY || '';
const SOLO_ISSUE = process.env.SOLO_ISSUE_NUMERO || '';

const GH_API = 'https://api.github.com';

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

const SHARED_HOSTING_DOMAINS = [
  'cloudinary.com', 'imgur.com', 'ibb.co', 'postimg.cc',
  'discord.com', 'discordapp.com', 'cdn.discordapp.com', 'media.discordapp.net',
  'telegra.ph', 'pastebin.com',
  'github.io', 'githubusercontent.com',
  'amazonaws.com', 'azurewebsites.net', 'herokuapp.com', 'netlify.app', 'vercel.app', 'firebaseapp.com', 'web.app',
  'blogspot.com', 'weebly.com', 'wixsite.com', 'glitch.me', 'repl.co', 'replit.dev', 'replit.app', 'pages.dev', 'surge.sh',
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

function tieneAprobacionManual(issue){
  const nombres = (issue.labels || []).map(l => (typeof l === 'string' ? l : l.name));
  return nombres.includes('aprobado-manual') || nombres.includes('confirmado');
}

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
      body: JSON.stringify({url: urlCompleta || `http://${domain}`, visibility:'unlisted'})
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

  let resultado = urlCompleta ? null : await buscarUrlscanExistente(domain);
  if(!resultado) resultado = await enviarNuevoUrlscan(domain, urlCompleta);
  if(!resultado) return {disponible:false};
  const overall = resultado.verdicts && resultado.verdicts.overall;
  if(!overall) return {disponible:false};
  return {disponible:true, malicious: !!overall.malicious, score: overall.score || 0, flagged: !!overall.malicious};
}

async function consultarUrlhaus(urlCompleta){
  if(!URLHAUS_KEY || !urlCompleta) return {disponible:false};
  try{
    const r = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
      method:'POST',
      headers:{'Auth-Key': URLHAUS_KEY, 'Content-Type':'application/x-www-form-urlencoded'},
      body: `url=${encodeURIComponent(urlCompleta)}`
    });
    if(!r.ok) return {disponible:false};
    const data = await r.json();
    if(data.query_status !== 'ok') return {disponible:true, malicious:false, flagged:false, encontrado:false};
    const enLinea = data.url_status === 'online';
    return {disponible:true, malicious:true, flagged:true, encontrado:true, enLinea, amenaza: data.threat || 'malware'};
  }catch(e){ return {disponible:false}; }
}

function leerLista(nombreArchivo){
  try{
  
    return fs.readFileSync(nombreArchivo, 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  }catch(e){ return []; }
}

function asegurarCarpeta(nombreArchivo){
  const dir = path.dirname(nombreArchivo);
  if(dir && dir !== '.') fs.mkdirSync(dir, {recursive:true});
}

function regenerarListasDerivadas(dominios, urlsCompletas){

  const sinProtegidos = dominios.filter(d => !esDominioDeConfianza(d));
  const excluidos = dominios.filter(d => esDominioDeConfianza(d));
  if(excluidos.length){
    console.log(`Excluidos por ser dominios de confianza (no se publican): ${excluidos.join(', ')}`);
  }
  const ordenados = [...new Set(sinProtegidos)].sort();
  const fecha = new Date().toISOString();

  asegurarCarpeta(CFG.archivos.blacklist);
  fs.writeFileSync(CFG.archivos.blacklist, ordenados.join('\n') + '\n');

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

  asegurarCarpeta(CFG.archivos.unbound);
  const unbound = [
    `# Bloqueo nativo para Unbound (sin módulo RPZ). Generado por AntiPhishingRD (${fecha}).`,
    `# Inclúyelo en unbound.conf con: include: "/ruta/a/este/archivo"`,
    ...ordenados.map(d => `local-zone: "${d}." always_nxdomain`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.unbound, unbound);

  asegurarCarpeta(CFG.archivos.pihole);
  const pihole = [
    `# Lista Pi-hole (formato hosts). Generado por AntiPhishingRD (${fecha}).`,
    ...ordenados.map(d => `0.0.0.0 ${d}`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.pihole, pihole);

  asegurarCarpeta(CFG.archivos.adguard);
  const adguard = [
    `! Lista AdGuard Home (sintaxis adblock). Generado por AntiPhishingRD (${fecha}).`,
    `! Agregar en Filtros > Listas de bloqueo DNS > Agregar lista de bloqueo personalizada`,
    ...ordenados.map(d => `||${d}^`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.adguard, adguard);

  asegurarCarpeta(CFG.archivos.dnsmasq);
  const dnsmasq = [
    `# Bloqueo para dnsmasq. Generado por AntiPhishingRD (${fecha}).`,
    `# Inclúyelo con: conf-file=/ruta/a/este/archivo (o colócalo en /etc/dnsmasq.d/)`,
    ...ordenados.map(d => `address=/${d}/0.0.0.0`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.dnsmasq, dnsmasq);

  asegurarCarpeta(CFG.archivos.firewall);
  const fw = [
    `# Feed de dominios bloqueados para pfSense (pfBlockerNG DNSBL) y OPNsense`,
    `# (bloqueador de dominios de Unbound). Generado por AntiPhishingRD (${fecha}).`,
    ...ordenados,
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.firewall, fw);

  asegurarCarpeta(CFG.archivos.mikrotik);
  const mikrotik = [
    `# Script RouterOS. Generado por AntiPhishingRD (${fecha}).`,
    `# Importar con: /import file-name=mikrotik-antiphishingrd.rsc`,
    `/ip dns static`,
    ...ordenados.map(d => `add name=${d} type=A address=0.0.0.0 comment="AntiPhishingRD"`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.mikrotik, mikrotik);

  asegurarCarpeta(CFG.archivos.squid);
  const squid = [
    `# ACL dstdomain para Squid. Generado por AntiPhishingRD (${fecha}).`,
    `# En squid.conf: acl antiphishingrd dstdomain "/ruta/a/este/archivo"`,
    `#                http_access deny antiphishingrd`,
    ...ordenados.map(d => `.${d}`),
    ''
  ].join('\n');
  fs.writeFileSync(CFG.archivos.squid, squid);

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

const PLAN_FILE = path.join(require('os').tmpdir(), 'antiphishingrd-plan-issues.json');

async function planificar(){
  if(!GITHUB_TOKEN || !OWNER || !REPO){
    console.log('Faltan credenciales de GitHub en el entorno, nada que hacer.');
    return;
  }

  const dominiosActuales = leerLista(CFG.archivos.blacklist);
  const setActual = new Set(dominiosActuales);
  const urlsActuales = new Set(CFG.archivos.blacklistUrls ? leerLista(CFG.archivos.blacklistUrls) : []);
  let huboCambios = false;
  let huboCambiosUrls = false;
  const acciones = [];

  const issues = await listaDeIssuesReportados();
  console.log(`Issues de reporte a procesar: ${issues.length}`);

  for(const issue of issues){
    const domain = extraerDominio(issue.body);
    if(!domain){
      acciones.push({numero: issue.number, comentario: 'No se pudo identificar el dominio en este reporte. Edítalo con el formato "Dominio: ejemplo.com" o ciérralo manualmente.'});
      continue;
    }

    const proveedor = esDominioDeConfianza(domain);
    if(proveedor){
      acciones.push({
        numero: issue.number,
        comentario: [
          `🛡️ **Dominio protegido, no se procesa.** \`${domain}\` pertenece a ${proveedor}, un proveedor reconocido en la lista de exclusión.`,
          '',
          'Este dominio nunca se agrega a la blacklist automáticamente, sin importar el resultado de los motores externos. Esto protege contra reportes maliciosos que busquen bloquear un servicio legítimo. Si de verdad detectaste phishing alojado bajo este proveedor (por ejemplo, una página fraudulenta en un subdominio de hosting gratuito), repórtalo directamente al proveedor además de aquí.'
        ].join('\n'),
        actualizacion: {state:'closed', title: `🛡️ Protegido: ${domain}`, labels:['reporte-dominio','dominio-protegido']}
      });
      continue;
    }

    const soloUrl = esSoloUrl(issue.body) || !!esHostingCompartido(domain);
    const urlCompleta = extraerUrlCompleta(issue.body);

    if(tieneAprobacionManual(issue)){
      if(soloUrl){
        if(!urlCompleta){
          acciones.push({numero: issue.number, comentario: `Tiene la etiqueta \`aprobado-manual\`, pero \`${domain}\` es hosting compartido y no se pudo leer la URL exacta en este reporte. Edítalo con el formato "URL analizada: https://..." para poder publicarlo.`});
          continue;
        }
        urlsActuales.add(urlCompleta);
        huboCambiosUrls = true;
        acciones.push({
          numero: issue.number,
          comentario: [
            `✅ **Aprobado manualmente.** Se agrega la URL exacta \`${urlCompleta}\` a la lista de URLs bloqueadas.`,
            '',
            `⚠️ El dominio \`${domain}\` **no** se agrega a ningún archivo de DNS/firewall, es una plataforma de hosting compartido.`
          ].join('\n'),
          actualizacion: {state:'closed', title: `✅ Confirmado: ${domain}`, labels:['reporte-dominio','confirmado','solo-url','aprobado-manual']}
        });
      }else{
        setActual.add(domain);
        huboCambios = true;
        acciones.push({
          numero: issue.number,
          comentario: `✅ **Aprobado manualmente.** Se agrega \`${domain}\` a la blacklist pública, la zona DNS RPZ, la lista de Pi-hole y el alias de firewall.`,
          actualizacion: {state:'closed', title: `✅ Confirmado: ${domain}`, labels:['reporte-dominio','confirmado','aprobado-manual']}
        });
      }
      continue;
    }

    if(soloUrl){
      if(!urlCompleta){
        acciones.push({numero: issue.number, comentario: `\`${domain}\` es una plataforma de hosting compartido, pero no se pudo leer la URL exacta en este reporte. Edítalo con el formato "URL analizada: https://..." o ciérralo manualmente.`});
        continue;
      }
      if(urlsActuales.has(urlCompleta)){
        acciones.push({
          numero: issue.number,
          comentario: `La URL \`${urlCompleta}\` ya está publicada en la lista de URLs exactas, no se requiere ninguna acción adicional. El dominio \`${domain}\` en sí nunca se bloquea, por ser hosting compartido.`,
          actualizacion: {state:'closed', title: `✅ Ya publicado: ${domain}`, labels:['reporte-dominio','ya-publicado','solo-url']}
        });
        continue;
      }

      console.log(`Verificando URL exacta ${urlCompleta} (dominio de hosting compartido: ${domain})…`);
      const [urlscan, urlhaus] = await Promise.all([consultarUrlscan(domain, urlCompleta), consultarUrlhaus(urlCompleta)]);
      let motoresDeAcuerdo = 0;
      if(urlscan.disponible){
        console.log(`  urlscan.io: ${urlscan.malicious ? 'MALICIOSO' : 'sin indicios'} (score ${urlscan.score})`);
        if(urlscan.flagged) motoresDeAcuerdo++;
      }
      if(urlhaus.disponible){
        console.log(`  URLhaus: ${urlhaus.encontrado ? `encontrado (${urlhaus.amenaza})` : 'sin coincidencias'}`);
        if(urlhaus.flagged) motoresDeAcuerdo++;
      }

      const seConfirma = motoresDeAcuerdo >= CFG.minMotoresExternosDeAcuerdo && (urlscan.disponible || urlhaus.disponible);

      if(seConfirma){
        urlsActuales.add(urlCompleta);
        huboCambiosUrls = true;
        acciones.push({
          numero: issue.number,
          comentario: [
            `✅ **Confirmado de forma independiente.** Se agrega la URL exacta \`${urlCompleta}\` a la lista de URLs bloqueadas.`,
            '',
            `⚠️ El dominio \`${domain}\` **no** se agrega a ningún archivo de DNS/firewall, es una plataforma de hosting compartido, y bloquear el dominio completo rompería el servicio para todos los demás usuarios. La URL exacta solo sirve para proxies con soporte de URL completa (Squid con url_regex) o extensiones de navegador, no para DNS.`
          ].join('\n'),
          actualizacion: {state:'closed', title: `✅ Confirmado: ${domain}`, labels:['reporte-dominio','confirmado','solo-url']}
        });
      }else{
        acciones.push({
          numero: issue.number,
          comentario: [
            '⏳ **No se confirma automáticamente todavía.** Las fuentes de verificación externas consultadas no alcanzaron el consenso mínimo para confirmar esta URL como maliciosa.',
            '',
            'Este reporte queda abierto para revisión manual. Si un administrador confirma que es malicioso, puede agregar la etiqueta `confirmado` (o `aprobado-manual`) a este issue para publicarlo en la próxima ejecución, sin depender de las fuentes externas.'
          ].join('\n'),
          actualizacion: {title: `⏳ Pendiente de revisión: ${domain}`, labels:['reporte-dominio','revision-manual','solo-url']}
        });
      }
      continue;
    }

    if(setActual.has(domain)){
      acciones.push({
        numero: issue.number,
        comentario: `El dominio \`${domain}\` ya está publicado en la blacklist, no se requiere ninguna acción adicional.`,
        actualizacion: {state:'closed', title: `✅ Ya publicado: ${domain}`, labels:['reporte-dominio','ya-publicado']}
      });
      continue;
    }

    console.log(`Verificando ${domain}…`);
    const [vt, urlscan] = await Promise.all([consultarVirusTotal(domain), consultarUrlscan(domain)]);

    let motoresDeAcuerdo = 0;
    if(vt.disponible){
      console.log(`  VirusTotal: ${vt.malicious}/${vt.total} motores lo marcan malicioso`);
      if(vt.flagged) motoresDeAcuerdo++;
    }
    if(urlscan.disponible){
      console.log(`  urlscan.io: ${urlscan.malicious ? 'MALICIOSO' : 'sin indicios'} (score ${urlscan.score})`);
      if(urlscan.flagged) motoresDeAcuerdo++;
    }

    const seConfirma = motoresDeAcuerdo >= CFG.minMotoresExternosDeAcuerdo && (vt.disponible || urlscan.disponible);

    if(seConfirma){
      setActual.add(domain);
      huboCambios = true;
      acciones.push({
        numero: issue.number,
        comentario: `✅ **Confirmado de forma independiente.** Se agrega \`${domain}\` a la blacklist pública, la zona DNS RPZ, la lista de Pi-hole y el alias de firewall.`,
        actualizacion: {state:'closed', title: `✅ Confirmado: ${domain}`, labels:['reporte-dominio','confirmado']}
      });
    }else{
      acciones.push({
        numero: issue.number,
        comentario: [
          '⏳ **No se confirma automáticamente todavía.** Las fuentes de verificación externas consultadas no alcanzaron el consenso mínimo para confirmarlo automáticamente.',
          '',
          'Este reporte queda abierto para revisión manual. Si confirmas que es malicioso, agrega la etiqueta `confirmado` (o `aprobado-manual`) a este issue para publicarlo en la próxima ejecución, sin depender de las fuentes externas.'
        ].join('\n'),
        actualizacion: {title: `⏳ Pendiente de revisión: ${domain}`, labels:['reporte-dominio','revision-manual']}
      });
    }
  }

  if(huboCambios || huboCambiosUrls){
    regenerarListasDerivadas([...setActual], [...urlsActuales]);
    console.log('Listas regeneradas con los nuevos dominios/URLs confirmados.');
  }else{
    console.log('Ningún dominio ni URL nuevo fue confirmado en esta pasada.');
  }

  fs.writeFileSync(PLAN_FILE, JSON.stringify(acciones, null, 2));
  console.log(`Plan de ${acciones.length} acción(es) sobre issues guardado (se aplica después de publicar).`);
}

async function aplicarPlan(){
  if(!fs.existsSync(PLAN_FILE)){
    console.log('No hay ningún plan de acciones pendiente que aplicar.');
    return;
  }
  const acciones = JSON.parse(fs.readFileSync(PLAN_FILE, 'utf8'));
  for(const a of acciones){
    if(a.comentario) await comentarIssue(a.numero, a.comentario);
    if(a.actualizacion) await actualizarIssue(a.numero, a.actualizacion);
  }
  fs.unlinkSync(PLAN_FILE);
  console.log(`${acciones.length} acción(es) aplicadas sobre issues de GitHub.`);
}

const modo = process.argv[2] || 'todo';
(async () => {
  try{
    if(modo === 'planificar') await planificar();
    else if(modo === 'aplicar') await aplicarPlan();
    else { await planificar(); await aplicarPlan(); }
  }catch(err){ console.error(err); process.exit(1); }
})();
