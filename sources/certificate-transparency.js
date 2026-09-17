const BRAND_KEYWORDS = [
  // Banca
  { keyword: 'banreservas', legit: ['banreservas.com'] },
  { keyword: 'bhd', legit: ['bhd.com.do'] },
  { keyword: 'bancopopular', legit: ['bancopopular.com.do', 'popularenlinea.com', 'popular.com.do'] },
  { keyword: 'scotiabank', legit: ['scotiabank.com.do', 'scotiabank.com'] },
  { keyword: 'banesco', legit: ['banesco.com.do'] },
  { keyword: 'apap', legit: ['apap.com.do'] },
  { keyword: 'bancovimenca', legit: ['bancovimenca.com'] },
  { keyword: 'bancocaribe', legit: ['bancocaribe.com.do'] },
  { keyword: 'bancoademi', legit: ['bancoademi.com.do', 'ademi.com.do'] },
  { keyword: 'promerica', legit: ['promerica.com.do'] },
  { keyword: 'bancentral', legit: ['bancentral.gov.do'] },
  { keyword: 'sib', legit: ['sib.gob.do'] },

  // Pagos
  { keyword: 'azul', legit: ['azul.com.do'] },

  // Telecomunicaciones y electricidad
  { keyword: 'claro', legit: ['claro.com.do'] },
  { keyword: 'altice', legit: ['alticedominicana.com.do', 'altice.com.do'] },
  { keyword: 'edesur', legit: ['edesur.com.do'] },
  { keyword: 'edenorte', legit: ['edenorte.com.do'] },
  { keyword: 'edeeste', legit: ['edeeste.com.do'] },
  { keyword: 'indotel', legit: ['indotel.gob.do'] },

  // Gobierno e instituciones públicas
  { keyword: 'dgii', legit: ['dgii.gov.do'] },
  { keyword: 'jce', legit: ['jce.gob.do'] },
  { keyword: 'tss', legit: ['tss.gob.do'] },
  { keyword: 'senasa', legit: ['senasa.gob.do'] },
  { keyword: 'migracion', legit: ['migracion.gob.do'] },
  { keyword: 'aduanas', legit: ['aduanas.gob.do'] },
  { keyword: 'loterianacional', legit: ['loterianacional.gob.do'] },
  { keyword: 'msp', legit: ['msp.gob.do'] },
  { keyword: 'presidencia', legit: ['presidencia.gob.do'] },
  { keyword: 'minerd', legit: ['minerd.gob.do'] },
  { keyword: 'pgr', legit: ['pgr.gob.do', 'ministeriopublico.gob.do'] },

  // Otros
  { keyword: 'arajet', legit: ['arajet.com'] },
];

function esLegit(host, legitList) {
  return legitList.some(l => host === l || host.endsWith('.' + l));
}

function dormir(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function consultarMarca(marca, legit, limiteFecha) {
  const encontrados = [];
  try {
    const r = await fetch(`https://crt.sh/?q=%25${encodeURIComponent(marca)}%25&output=json`, {
      headers: { 'User-Agent': 'AntiPhishingRD-CT-Monitor/1.0 (+https://antiphishingrd.org)' }
    });
    if (!r.ok) {
      console.error(`Certificate Transparency: crt.sh respondió ${r.status} para "${marca}"`);
      return encontrados;
    }
    const registros = await r.json();
    const vistos = new Set();
    for (const reg of registros) {
      const marcaTiempo = Date.parse((reg.entry_timestamp || '').replace(' ', 'T') + 'Z');
      if (Number.isNaN(marcaTiempo) || marcaTiempo < limiteFecha) continue;

      const nombres = (reg.name_value || '').split('\n');
      for (let nombre of nombres) {
        nombre = nombre.trim().toLowerCase().replace(/^\*\./, '');
        if (!nombre || vistos.has(nombre)) continue;
        vistos.add(nombre);
        if (/\s/.test(nombre) || !nombre.includes('.')) continue;
        if (!nombre.includes(marca)) continue;
        if (esLegit(nombre, legit)) continue;
        encontrados.push({ domain: nombre, source: `certificate-transparency:${marca}` });
      }
    }
  } catch (e) {
    console.error(`Certificate Transparency: fallo consultando "${marca}":`, e.message);
  }
  return encontrados;
}

async function fetchCertificateTransparencyCandidates({ maxHorasAntiguedad = 26 } = {}) {
  const limiteFecha = Date.now() - maxHorasAntiguedad * 60 * 60 * 1000;
  const resultados = [];

  for (const { keyword, legit } of BRAND_KEYWORDS) {
    const encontrados = await consultarMarca(keyword, legit, limiteFecha);
    resultados.push(...encontrados);
    await dormir(1200);
  }

  return resultados;
}

module.exports = { fetchCertificateTransparencyCandidates, BRAND_KEYWORDS };
