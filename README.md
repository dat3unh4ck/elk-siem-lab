# SIEM con ELK Stack — ingesta, detección y respuesta

Laboratorio SOC completo y reproducible sobre Docker Compose: desde que una línea de log
entra en crudo hasta que se convierte en una alerta accionable, se enriquece con Threat
Intelligence y se investiga siguiendo NIST SP 800-61.

No parto de una consola ya hecha. Construí y documenté cada pieza —ingesta, parsing,
enriquecimiento, detección, visualización— aquí.

```
                 ┌──────────┐     ┌─────────────────────────────┐     ┌───────────────┐
  /var/log  ───► │ Filebeat │ ──► │          Logstash           │ ──► │ Elasticsearch │
                 └──────────┘     │  1 Grok  2 Fecha  3 Categoría│     └───────┬───────┘
                                  │  4 IP    5 GeoIP  6 Severidad│             │
                                  │            7 Limpieza        │             │
                                  └─────────────────────────────┘             │
                                                                               ▼
   scripts/enrich_ips.py ──► AbuseIPDB + VirusTotal ──► threat-intel-ips ──► ┌────────┐
                                                                             │ Kibana │
                                        5 reglas SIEM + 5 reglas Sigma ────► │ SOC    │
                                                                             └────────┘
```

| | |
|---|---|
| Eventos ingestados | 63.883 |
| Reglas de detección SIEM | 5, mapeadas a MITRE ATT&CK |
| Reglas Sigma portables | 5, convertidas y verificadas en Lucene |
| Técnicas ATT&CK cubiertas | T1110, T1548, T1071, T1098, T1046 |
| Paneles del dashboard SOC | 7 + mapa de geolocalización |
| MTTD medido en la investigación | ~5 minutos |

## Stack

Elasticsearch, Logstash, Kibana y Filebeat 8.17.0 sobre Docker Compose, con
`xpack.security` habilitada. Detección con Kibana Security SIEM, Sigma y `sigma-cli`.
Enriquecimiento en Python 3. Frameworks: MITRE ATT&CK v15, NIST SP 800-61 Rev. 2, Cyber Kill
Chain.

Lo probé en macOS ARM64 (M4 Pro, 24 GB RAM). Funciona igual en Linux ajustando
`HOST_LOG_DIR`.

## Puesta en marcha

Requisitos: Docker Desktop (o Docker Engine + Compose) y unos 4 GB de RAM libres.

```bash
git clone https://github.com/dat3unh4ck/elk-siem-lab.git
cd elk-siem-lab

cp .env.example .env
# rellenar .env. Para las tres encryption keys:  openssl rand -hex 24

docker compose up -d          # la primera vez descarga ~2-3 GB de imágenes
./scripts/setup.sh            # contraseñas, licencia Trial e index template
docker compose restart kibana
```

Kibana queda en http://localhost:5601 (usuario `elastic`, la contraseña del `.env`).

Después hay que crear el data view `macos-logs-*` con campo temporal `@timestamp`, y
entonces:

```bash
sudo ./scripts/inject-test-events.sh    # 10 eventos de prueba con IPs públicas reales
```

Las reglas de detección se crean siguiendo [`detection-rules/README.md`](detection-rules/README.md).

## Estructura

```
.
├── docker-compose.yml              Los 4 servicios, con healthchecks y dependencias
├── .env.example                    Plantilla de configuración (el .env real no se sube)
├── filebeat/filebeat.yml           Recolección de system.log, install.log y wifi.log
├── logstash/pipeline/logstash.conf Pipeline de 7 etapas — el corazón del laboratorio
├── kibana/kibana.yml               Encryption keys del Detection Engine
├── elasticsearch/
│   └── index-template.json         Mapea geoip.geo.location como geo_point (para Maps)
├── sigma-rules/                    5 reglas Sigma portables
├── detection-rules/README.md       Las 5 reglas de Kibana Security y su cobertura ATT&CK
├── queries/kql.md                  Consultas KQL de triaje e investigación
├── scripts/
│   ├── setup.sh                    Configuración post-despliegue, idempotente
│   ├── inject-test-events.sh       Generación de eventos de prueba
│   └── enrich_ips.py               Enriquecimiento con AbuseIPDB y VirusTotal
└── docs/
    └── investigacion-portscan.md   Investigación completa de un incidente (NIST SP 800-61)
```

## El pipeline

Logstash hace siete cosas con cada línea, y ese es el trabajo de verdad del laboratorio:

1. Grok descompone la línea syslog en `hostname`, `process`, `pid` y `log_message`.
2. Normalización temporal: el timestamp del log pasa a ser `@timestamp`, no la hora de
   ingesta.
3. Categorización por proceso emisor.
4. Extracción de IP del cuerpo del mensaje con un patrón que cubre varias redacciones.
5. GeoIP sobre esa IP: país, ciudad y coordenadas, sin servicios externos.
6. Severidad automática en cuatro niveles según el contenido del mensaje.
7. Limpieza de los campos ya normalizados.

Los eventos sin parsear quedan marcados con `_grok_parse_failure`, así que la cobertura del
pipeline es medible: `tags : "_grok_parse_failure"` dice cuánta visibilidad se está
perdiendo.

## Detección

Cinco reglas en Kibana Security, cada una con su equivalente Sigma portable en
[`sigma-rules/`](sigma-rules/). La regla Sigma es la fuente de verdad del detection logic; la
de Kibana es su implementación en este SIEM concreto.

| Técnica | Táctica | Regla |
|---|---|---|
| [T1110](https://attack.mitre.org/techniques/T1110/) | Credential Access | Brute Force |
| [T1548](https://attack.mitre.org/techniques/T1548/) | Privilege Escalation | Escalada de privilegios vía sudo |
| [T1071](https://attack.mitre.org/techniques/T1071/) | Command and Control | Conexión saliente sospechosa |
| [T1098](https://attack.mitre.org/techniques/T1098/) | Persistence | Modificación de fichero crítico |
| [T1046](https://attack.mitre.org/techniques/T1046/) | Discovery | Escaneo de puertos |

Conversión a la sintaxis del backend:

```bash
pip install sigma-cli pySigma-backend-elasticsearch
sigma convert -t lucene --without-pipeline sigma-rules/
```

Las reglas usan el campo `log_message` que genera el propio pipeline de Logstash, así que no
hace falta una processing pipeline de Sigma que traduzca nombres de campo. La salida son
exactamente las consultas de [`detection-rules/README.md`](detection-rules/README.md).

## Threat Intelligence

[`scripts/enrich_ips.py`](scripts/enrich_ips.py) extrae de Elasticsearch las IPs observadas,
descarta las privadas y reservadas, consulta AbuseIPDB y VirusTotal respetando sus rate
limits, calcula un veredicto unificado y escribe el resultado en el índice `threat-intel-ips`,
propagando un resumen a los documentos originales para usarlo en dashboards.

```bash
export $(grep -v '^#' .env | xargs)
python3 scripts/enrich_ips.py --dry-run   # muestra lo que haría, sin escribir
python3 scripts/enrich_ips.py
```

Funciona con una sola de las dos API keys. Cachea los resultados para no reconsultar IPs ya
vistas y reintenta los fallos transitorios.

## Investigación de incidente

[`docs/investigacion-portscan.md`](docs/investigacion-portscan.md) recorre un caso completo de
principio a fin: alerta de escaneo de puertos, triaje con los indicadores que descartan el
falso positivo, cuatro consultas de análisis, pivoteo entre las dos IPs implicadas, mapeo
ATT&CK, veredicto y escalado a L2 con las acciones de contención.

La sección de lecciones aprendidas la escribí autocrítica a propósito: la regla que disparó es
de coincidencia simple y debería ser de tipo `threshold`.

## Limitaciones

Es un laboratorio, y conviene decir en qué se nota:

- SSL deshabilitado entre componentes. En producción el tráfico interno de la pila va cifrado.
- Nodo único de Elasticsearch, sin réplicas: el estado del clúster es `yellow` por diseño.
- Reglas de coincidencia simple. Detectan la firma, no el comportamiento. Las de Brute Force y
  Port Scan deberían ser `threshold` agrupando por `alert_ip`.
- Eventos de seguridad simulados. Las IPs son públicas reales para que GeoIP resuelva, pero los
  eventos se inyectan en el log; no hay ataque real contra la máquina.
- Sin correlación entre reglas. Cada alerta se evalúa aislada.

## Siguientes pasos

- [ ] Convertir Brute Force y Port Scan a reglas `threshold`
- [ ] Regla de correlación Reconocimiento → Acceso Inicial desde la misma IP
- [ ] Exportar las reglas de Kibana como NDJSON para versionarlas en el repo
- [ ] Sustituir las claves de API por un gestor de secretos
- [ ] Validar la cobertura con Atomic Red Team

## Más

El writeup completo con capturas de cada paso está en
[mi Notion](https://jonathasapuntes.notion.site/Jonathas-Carneiro-Ciberseguridad-Defensiva-SOC-2de10ea9b490803d9cc3c49ec44924e3),
y el proceso de construcción lo cuento en [@DateUnH4ck](https://www.youtube.com/@DateUnH4ck).

---

Jonathas Carneiro — Blue Team / SOC · [LinkedIn](https://www.linkedin.com/in/jonathascarneiro-soc/)
