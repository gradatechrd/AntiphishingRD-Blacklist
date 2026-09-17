const fs = require('fs');
const path = require('path');

const CFG = JSON.parse(fs.readFileSync(path.join(__dirname, 'consenso.config.json'), 'utf8'));

const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const [OWNER, REPO] = (process.env.GITHUB_REPOSITORY || '').split('/');
const GH_API = 'https://api.github.com';

const { fetchPhishStatsCandidates } = require('../sources/phishstats');
const { fetchPhishingDatabaseCandidates } = require('../sources/phishing-database');
const { fetchCertificateTransparencyCandidates } = require('../sources/certificate-transparency');

function dominioExcluidoPorPolitica(domain) {
  if (/\.do$/i.test(domain)) return true;
  if (/\.gov$/i.test(domain)) return true;
  if (/\.(gob|gov)\.[a-z]{2,}$/i.test(domain)) return true;
  return false;
}

function ghHeaders() {
  return {
    'Authorization': `Bearer ${GITHUB_TOKEN}`,
    'Accept': 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
}

function extraerDominio(body) {
  const m = /Dominio:\s*([^\s]+)/i.exec(body || '');
  return m ? m[1].trim().toLowerCase().replace(/[.,;]+$/, '') : null;
}

function leerLista(nombreArchivo) {
  try {
    return fs.readFileSync(nombreArchivo, 'utf8').split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
  } catch (e) { return []; }
}

async function dominiosYaConocidos() {
  const conocidos = new Set(leerLista(CFG.archivos.blacklist));

  let page = 1;
  while (true) {
    const r = await fetch(`${GH_API}/repos/${OWNER}/${REPO}/issues?labels=reporte-dominio&state=all&per_page=100&page=${page}`, { headers: ghHeaders() });
    if (!r.ok) break;
    const issues = await r.json();
    if (!issues.length) break;
    for (const issue of issues) {
      const d = extraerDominio(issue.body);
      if (d) conocidos.add(d);
    }
    if (issues.length < 100) break;
    page++;
  }
  return conocidos;
}

async function crearIssue(domain, sources) {
  const url = `https://${domain}/`;
  const esMonitoreoDeMarca = sources.some(s => s.startsWith('certificate-transparency:'));
  const body = [
    `Dominio: ${domain}`,
    `URL analizada: ${url}`,
    `Alcance del bloqueo: dominio-completo`,
    '',
    `Fuente externa: ${sources.join(', ')}`,
    '',
    esMonitoreoDeMarca
      ? 'Detectado por monitoreo proactivo de certificados SSL (Certificate Transparency): se emitió un certificado nuevo para un dominio que contiene el nombre de una marca vigilada. Esto NO significa que sea malicioso — muchos resultados serán legítimos (la propia marca, revendedores, fans, prensa). El workflow lo verifica de forma independiente (VirusTotal/urlscan.io/Google Safe Browsing) antes de considerar publicarlo.'
      : 'Reportado automáticamente por fuentes externas de threat intelligence (PhishStats / Phishing.Database), sin intervención de un visitante. El workflow de GitHub Actions verifica este dominio de forma independiente (VirusTotal/urlscan.io) antes de publicarlo.',
  ].join('\n');

  const labels = ['reporte-dominio', 'fuente-externa'];
  if (esMonitoreoDeMarca) labels.push('monitoreo-marca');

  const r = await fetch(`${GH_API}/repos/${OWNER}/${REPO}/issues`, {
    method: 'POST',
    headers: ghHeaders(),
    body: JSON.stringify({
      title: `⏳ Pendiente de revisión: ${domain}`,
      body,
      labels,
    }),
  });
  if (!r.ok) {
    console.error(`No se pudo crear el issue para ${domain}: ${r.status}`);
    return false;
  }
  return true;
}

async function main() {
  if (!GITHUB_TOKEN || !OWNER || !REPO) {
    console.log('Faltan credenciales de GitHub en el entorno, nada que hacer.');
    return;
  }

  const [phishstatsResult, phishingDbResult, ctResult] = await Promise.allSettled([
    fetchPhishStatsCandidates({ limit: 200, minScore: 3 }),
    fetchPhishingDatabaseCandidates({ feed: 'newToday' }),
    fetchCertificateTransparencyCandidates({ maxHorasAntiguedad: 26 }),
  ]);

  const merged = new Map();
  for (const result of [phishstatsResult, phishingDbResult, ctResult]) {
    if (result.status !== 'fulfilled') {
      console.error('Una fuente externa falló:', result.reason?.message || result.reason);
      continue;
    }
    for (const item of result.value) {
      if (dominioExcluidoPorPolitica(item.domain)) continue;
      if (!merged.has(item.domain)) merged.set(item.domain, new Set());
      merged.get(item.domain).add(item.source);
    }
  }

  console.log(`Candidatos únicos tras filtrar por política: ${merged.size}`);

  const conocidos = await dominiosYaConocidos();
  let creados = 0;

  for (const [domain, sources] of merged.entries()) {
    if (conocidos.has(domain)) continue;
    const ok = await crearIssue(domain, Array.from(sources));
    if (ok) creados++;
    conocidos.add(domain);
  }

  console.log(`${creados} issue(s) nuevo(s) creado(s) a partir de fuentes externas.`);
}

main().catch(err => { console.error(err); process.exit(1); });
