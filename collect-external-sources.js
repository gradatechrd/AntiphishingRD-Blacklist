const { fetchPhishStatsCandidates } = require("./sources/phishstats");
const { fetchPhishingDatabaseCandidates } = require("./sources/phishing-database");

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

async function collectExternalCandidates() {
  const results = await Promise.allSettled([
    fetchPhishStatsCandidates({ limit: 200, minScore: 3 }),
    fetchPhishingDatabaseCandidates({ feed: "newToday" }),
  ]);

  const merged = new Map();

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
