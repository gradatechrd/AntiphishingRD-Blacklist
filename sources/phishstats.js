const PHISHSTATS_BASE_URL = "https://api.phishstats.info/api/phishing";

async function fetchPhishStatsCandidates({ limit = 200, minScore = 3 } = {}) {

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

  const candidates = (Array.isArray(data) ? data : [])
    .filter((entry) => (entry.score ?? 0) >= minScore)
    .map((entry) => ({
      domain: normalizeDomain(entry.host || extractHostFromUrl(entry.url)),
      url: entry.url,
      score: entry.score,
      source: "phishstats",
    }))
    .filter((c) => !!c.domain);

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
