/**
 * sources/phishstats.js
 *
 * Cliente para PhishStats (https://phishstats.info).
 * Devuelve una lista de dominios candidatos (recientes) para que el
 * pipeline principal los pase por la verificación existente
 * (VirusTotal / urlscan.io) antes de publicarlos en el blacklist.
 *
 * API docs: https://phishstats.info/#apidoc
 *
 * Uso de API key (opcional pero recomendado):
 *   - Sin key: 50 requests/día por IP
 *   - Con key gratis (registro en el sitio): 150/día
 *   Configura PHISHSTATS_API_KEY como secret del repo/Action si la usas.
 */

const PHISHSTATS_BASE_URL = "https://api.phishstats.info/api/phishing";

/**
 * Obtiene los dominios de phishing más recientes reportados por PhishStats.
 *
 * @param {Object} opts
 * @param {number} [opts.limit=200] - Cantidad máxima de registros a traer.
 * @param {number} [opts.minScore=3] - Filtra por phishscore mínimo (0-10, más alto = más confianza).
 * @returns {Promise<{domain: string, url: string, score: number, source: string}[]>}
 */
async function fetchPhishStatsCandidates({ limit = 200, minScore = 3 } = {}) {
  // _sort=-date trae lo más reciente primero
  const query = `_size=${limit}&_sort=-date`;
  const url = `${PHISHSTATS_BASE_URL}?${query}`;

  const headers = {};
  if (process.env.PHISHSTATS_API_KEY) {
    headers["X-API-Key"] = process.env.PHISHSTATS_API_KEY;
  }

  const res = await fetch(url, { headers });
  if (!res.ok) {
    throw new Error(`PhishStats API error: ${res.status} ${res.statusText}`);
  }

  const data = await res.json();

  // La respuesta trae objetos con campos: id, url, host (dominio), ip,
  // asn, asn_name, country, date, title, tld, score
  const candidates = (Array.isArray(data) ? data : [])
    .filter((entry) => (entry.score ?? 0) >= minScore)
    .map((entry) => ({
      domain: normalizeDomain(entry.host || extractHostFromUrl(entry.url)),
      url: entry.url,
      score: entry.score,
      source: "phishstats",
    }))
    .filter((c) => !!c.domain);

  // Deduplicar por dominio
  const seen = new Set();
  return candidates.filter((c) => {
    if (seen.has(c.domain)) return false;
    seen.add(c.domain);
    return true;
  });
}

function extractHostFromUrl(rawUrl) {
  try {
    return new URL(rawUrl).hostname;
  } catch {
    return null;
  }
}

function normalizeDomain(host) {
  if (!host) return null;
  return host.trim().toLowerCase().replace(/^www\./, "");
}

module.exports = { fetchPhishStatsCandidates };
