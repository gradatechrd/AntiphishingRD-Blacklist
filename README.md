# antiphishingrd-blacklist — plantilla del repositorio de blacklist

Este repositorio es **independiente del sitio web**. Su único trabajo es:

1. Recibir reportes de dominios como issues (los abre el botón "Reportar" del
   sitio, con la etiqueta `reporte-dominio`).
2. Verificar cada dominio de forma automática e independiente contra
   VirusTotal y urlscan.io — nunca confía en lo que el navegador de quien
   reportó ya calculó.
3. Si hay suficiente consenso externo, publicar el dominio en `blacklist.txt`
   y regenerar los archivos derivados para DNS y firewall.

## 1. Crear el repositorio

1. Crea un repositorio público en GitHub, por ejemplo `antiphishingrd-blacklist`.
2. Sube **todo el contenido de esta carpeta** (`.github/`, `scripts/`,
   `blacklist.txt`, `dns/`, `firewall/`) a la rama `main`.
3. En el sitio, edita `config.js` → sección `github`:
   ```js
   github: {
     owner: 'tu-usuario',
     repo: 'antiphishingrd-blacklist',
     branch: 'main',
     path: 'blacklist.txt',
     dnsRpzPath: 'dns/rpz-antiphishingrd.txt',
     piholePath: 'dns/pihole-antiphishingrd.txt',
     firewallPath: 'firewall/pfsense-alias.txt',
     issueLabel: 'reporte-dominio'
   }
   ```

## 2. Crear las etiquetas (labels) del repositorio

En "Issues" → "Labels", crea: `reporte-dominio`, `confirmado-automatico`,
`revision-manual`, `confirmado`, `ya-publicado`. GitHub las crea solas la
primera vez que el workflow intenta aplicarlas, pero es más prolijo tenerlas
de antemano con una descripción.

## 3. Configurar las claves de verificación (Settings → Secrets and variables → Actions)

| Secret | De dónde sacarlo | Qué pasa si no lo configuras |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | Cuenta gratuita en [virustotal.com](https://www.virustotal.com/gui/join-us) → tu perfil → API Key | El workflow no puede confirmar automáticamente ningún dominio; todo queda en revisión manual (es la opción segura por defecto). |
| `URLSCAN_API_KEY` | Cuenta gratuita en [urlscan.io](https://urlscan.io/user/signup) → Settings → API | Igual que arriba: sin esta clave, urlscan.io no participa en el consenso. |

`GITHUB_TOKEN` no hay que crearlo: GitHub lo genera solo para cada ejecución
del workflow, con permisos ya limitados a este repositorio (ver
`permissions:` en el workflow).

## 4. Cómo decide el workflow si confirma un dominio

Editable en `scripts/consenso.config.json`:

- `minMotoresExternosDeAcuerdo` (por defecto 1): cuántos motores externos
  (VirusTotal, urlscan.io) deben coincidir en que el dominio es malicioso.
  Súbelo a 2 si prefieres exigir que ambos coincidan antes de publicar nada.
- `virusTotal.minMotoresMaliciosos` (por defecto 3): cuántos motores
  antivirus dentro de VirusTotal deben marcarlo malicioso para que cuente
  como "de acuerdo".

Si ninguna de las dos claves está configurada, el workflow **nunca** publica
nada automáticamente — deja el issue abierto marcado `revision-manual` con
una explicación, para que una persona lo revise y lo agregue a mano si
corresponde. Esto es intencional: nunca se bloquea un dominio en producción
sin que algo externo lo haya confirmado.

## 5. Archivos que genera automáticamente

| Archivo | Formato | Para qué sirve |
|---|---|---|
| `blacklist.txt` | un dominio por línea | Lista simple, fuente de verdad |
| `dns/rpz-antiphishingrd.txt` | zona RPZ (BIND / Unbound) | Bloqueo a nivel de resolutor DNS |
| `dns/pihole-antiphishingrd.txt` | `0.0.0.0 dominio` | Lista de bloqueo para Pi-hole / AdGuard Home |
| `firewall/pfsense-alias.txt` | un dominio por línea | Alias de dominios para pfSense/OPNsense (pfBlockerNG DNSBL o Unbound blocklist) |

Cada uno de estos cuatro archivos se sirve tal cual desde
`raw.githubusercontent.com` — el panel del sitio ya arma esos enlaces usando
los valores de `config.js`.

## 6. Probarlo sin esperar un reporte real

"Actions" → "Verificar reportes y actualizar blacklist/DNS/firewall" →
"Run workflow" lo ejecuta manualmente sobre cualquier issue abierto con la
etiqueta `reporte-dominio`. También corre solo cada 6 horas por si algo
quedó pendiente de una corrida anterior.
