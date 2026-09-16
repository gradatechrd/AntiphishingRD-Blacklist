const FEEDS = {
  newToday:
    "https://cdn.jsdelivr.net/gh/Phishing-Database/Phishing.Database@master/phishing-domains-NEW-today.txt",
  newLastHour:
    "https://cdn.jsdelivr.net/gh/Phishing-Database/Phishing.Database@master/phishing-domains-NEW-last-hour.txt",
};

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
