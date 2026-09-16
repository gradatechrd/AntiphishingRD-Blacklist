/**
 * collect-external-sources.js
 *
 * Punto de integración con tu pipeline actual.
 *
 * Este script SOLO recolecta y deduplica candidatos de PhishStats y
 * Phishing.Database. NO los publica directamente al blacklist: la idea
 * es que su salida (un array de dominios) se pase a la misma función de
 * verificación que ya usas con VirusTotal/urlscan.io, exactamente igual
 * que como tratas los dominios reportados manualmente.
 *
 * Integración típica en tu Action / script principal:
 *
 *   const { collectExternalCandidates } = require("./collect-external-sources");
 *   const { verifyDomain } = require("./verify"); // tu función existente
 *
 *   const candidates = await collectExternalCandidates();
 *   for (const candidate of candidates) {
 *     const result = await verifyDomain(candidate.domain); // VT + urlscan
 *     if (result.isMalicious) {
 *       addToBlacklist(candidate.domain, { sources: candidate.sources });
 *     }
 *   }
 *
 * Recuerda: tu política vigente de excluir .do / dominios gubernamentales
 * debe aplicarse aquí también (ver EXCLUDED_TLDS abajo) para no meter
 * ruido a la cola de verificación.
 */

const { fetchPhishStatsCandidates } = require("./sources/phishstats");
const { fetchPhishingDatabaseCandidates } = require("./sources/phishing-database");

// Misma política que ya aplicas al blacklist: nunca incluir .do ni
// dominios gubernamentales de ningún país.
const EXCLUDED_TLD_PATTERNS = [
  /\.do$/i,
  /\.com\.do$/i,
  /\.org\.do$/i,
  /\.edu\.do$/i,
  /\.net\.do$/i,
  /\.web\.do$/i,
  /\.sld\.do$/i,
  /\.art\.do$/i,
  /\.gov(\.[a-z]{2})?$/i,
  /\.gob(\.[a-z]{2})?$/i,
];

function isExcluded(domain) {
  return EXCLUDED_TLD_PATTERNS.some((pattern) => pattern.test(domain));
}

/**
 * Recolecta y fusiona candidatos de todas las fuentes externas.
 * Cada dominio resultante lleva la lista de fuentes que lo reportaron,
 * útil para trazabilidad en el commit del bot.
 *
 * @returns {Promise<{domain: string, sources: string[]}[]>}
 */
async function collectExternalCandidates() {
  const results = await Promise.allSettled([
    fetchPhishStatsCandidates({ limit: 200, minScore: 3 }),
    fetchPhishingDatabaseCandidates({ feed: "newToday" }),
  ]);

  const merged = new Map(); // domain -> Set(sources)

  for (const result of results) {
    if (result.status !== "fulfilled") {
      console.error("Fuente externa falló:", result.reason?.message || result.reason);
      continue;
    }
    for (const item of result.value) {
      if (isExcluded(item.domain)) continue;
      if (!merged.has(item.domain)) {
        merged.set(item.domain, new Set());
      }
      merged.get(item.domain).add(item.source);
    }
  }

  return Array.from(merged.entries()).map(([domain, sources]) => ({
    domain,
    sources: Array.from(sources),
  }));
}

module.exports = { collectExternalCandidates, isExcluded };

// Permite correrlo standalone para depurar: `node collect-external-sources.js`
if (require.main === module) {
  collectExternalCandidates()
    .then((candidates) => {
      console.log(`Total candidatos únicos: ${candidates.length}`);
      console.log(candidates.slice(0, 20));
    })
    .catch((err) => {
      console.error("Error recolectando fuentes:", err);
      process.exit(1);
    });
}
