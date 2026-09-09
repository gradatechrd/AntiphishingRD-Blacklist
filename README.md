# antiphishingrd-blacklist — plantilla del repositorio de blacklist

Este repositorio es **independiente del sitio web**. Su único trabajo es:

1. Recibir reportes de dominios como issues (los abre el botón "Reportar" del
   sitio, con la etiqueta `reporte-dominio`).
2. Verificar cada dominio de forma automática e independiente contra
   VirusTotal y urlscan.io — nunca confía en lo que el navegador de quien
   reportó ya calculó.
3. Si hay suficiente consenso externo, publicar el dominio en `blacklist.txt`
   y regenerar los archivos derivados para DNS y firewall.
