/**
 * sources/phishing-database.js
 *
 * Cliente para el repositorio "Phishing.Database"
 * (https://github.com/Phishing-Database/Phishing.Database).
 *
 * Es un repo abierto que publica listas de texto plano (ACTIVE / INACTIVE,
 * NEW-last-hour, NEW-today, etc). Aquí consumimos las listas "NEW" que
 * representan dominios reportados recientemente, para pasarlos por tu
 * verificación (VirusTotal/urlscan.io) antes de publicarlos.
 *
 * No requiere API key: son archivos raw servidos vía GitHub / jsDelivr.
 */

// Usamos jsDelivr como CDN sobre el repo de GitHub (más estable ante rate
// limits que raw.githubusercontent.com para consumo automatizado frecuente).
const FEEDS = {
  newToday:
    "https://cdn.jsdelivr.net/gh/Phishing-Database/Phishing.Database@master/phishing-domains-NEW-today.txt",
  newLastHour:
    "https://cdn.jsdelivr.net/gh/Phishing-Database/Phishing.Database@master/phishing-domains-NEW-last-hour.txt",
};

/**
 * Descarga y parsea una lista de dominios de Phishing.Database.
 *
 * @param {Object} opts
 * @param {"newToday"|"newLastHour"} [opts.feed="newToday"]
 * @returns {Promise<{domain: string, source: string}[]>}
 */
async function fetchPhishingDatabaseCandidates({ feed = "newToday" } = {}) {
  const url = FEEDS[feed];
  if (!url) {
    throw new Error(`Feed desconocido: ${feed}. Usa: ${Object.keys(FEEDS).join(", ")}`);
  }

  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Phishing.Database fetch error: ${res.status} ${res.statusText}`);
  }

  const text = await res.text();

  const domains = text
    .split("\n")
    .map((line) => line.trim().toLowerCase())
    .filter((line) => line && !line.startsWith("#"));

  const seen = new Set();
  const candidates = [];
  for (const domain of domains) {
    if (seen.has(domain)) continue;
    seen.add(domain);
    candidates.push({ domain, source: "phishing-database" });
  }

  return candidates;
}

module.exports = { fetchPhishingDatabaseCandidates };
