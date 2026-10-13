# Investigación SOC L1 — Escaneo de puertos (T1046)

Caso: reconocimiento activo externo detectado por la regla *Reconocimiento — Escaneo de
puertos*.
Metodología: NIST SP 800-61 Rev. 2 — Alerta → Triaje → Análisis → Enriquecimiento → Mapeo
ATT&CK → Veredicto → Contención → Lecciones aprendidas.

## 1. Alerta recibida

| Campo | Detalle |
|---|---|
| Regla | Reconocimiento — Escaneo de puertos detectado |
| Severidad | High (Risk Score 73) |
| MITRE ATT&CK | Discovery → T1046 (Network Service Discovery) |
| Timestamp | 17 may 2026, 20:43:25 |
| Evento original | `ALERT: Port scan detected from 177.72.82.22 - 500 ports scanned in 5 seconds` |
| Fuente | `/var/log/host/system.log` |

## 2. Triaje — ¿verdadero o falso positivo?

| Indicador | Observación | Lectura |
|---|---|---|
| Volumen | 500 puertos en 5 s = 100 puertos/s | Incompatible con tráfico legítimo |
| Patrón | Barrido secuencial masivo | Firma de herramienta automatizada (Nmap, Masscan) |
| Origen | `177.72.82.22`, fuera de los rangos internos | Externo, no inventariado |
| Horario | Fuera de la ventana de actividad habitual | Refuerza la hipótesis |

Decido verdadero positivo, prioridad alta.

## 3. Análisis de logs

Toda la actividad de la IP:
```
alert_ip : "177.72.82.22"
```
Solo eventos de escaneo. No hay explotación posterior.

¿Hay más IPs escaneando?
```
log_message : "*Port scan*"
```
Aparece una segunda: `5.160.218.45`.

¿Actividad posterior de alguna de las dos?
```
alert_ip : "177.72.82.22" OR alert_ip : "5.160.218.45"
```
Ninguna. Los escaneos no derivaron en intento de acceso.

Contexto del momento:
```
severidad : "critica"
```
Hay otros eventos críticos simultáneos —fuerza bruta, C2, sudo no autorizado—, pero desde IPs
distintas y sin solape temporal con los escaneos. Concluyo que son incidentes independientes,
no una cadena coordinada.

## 4. Enriquecimiento

| Campo | IP 1 | IP 2 |
|---|---|---|
| IP | `177.72.82.22` | `5.160.218.45` |
| País (GeoIP) | Brasil | Irán |
| Puertos | 500 en 5 s | 300 en 2 s |
| Ratio | 100 p/s | 150 p/s |
| Post-escaneo | Sin actividad | Sin actividad |

La geolocalización salió del propio pipeline (etapa 5), sin consultar servicios externos. El
enriquecimiento con reputación (AbuseIPDB, VirusTotal) está automatizado en
[`../scripts/enrich_ips.py`](../scripts/enrich_ips.py).

## 5. Mapeo MITRE ATT&CK

| Campo | Valor |
|---|---|
| Táctica | Discovery (TA0007) |
| Técnica | T1046 — Network Service Discovery |
| Fase Kill Chain | Reconocimiento (precede a Weaponization y Delivery) |
| Riesgo | Alto — los servicios descubiertos son candidatos a explotación |

## 6. Veredicto

| Campo | Valor |
|---|---|
| Clasificación | Verdadero Positivo |
| Tipo | Reconocimiento activo externo |
| Impacto actual | Bajo — sin explotación observada |
| Riesgo potencial | Alto — precursor típico de ataque |
| MTTD | ~5 minutos |

## 7. Contención recomendada (escalado a L2)

1. Bloquear `177.72.82.22` y `5.160.218.45` en el firewall perimetral.
2. Revisar los logs del firewall para identificar qué puertos respondieron SYN-ACK.
3. Consultar ambas IPs en VirusTotal, AbuseIPDB y Shodan.
4. Monitorización intensificada 24–48 h sobre los puertos expuestos.
5. Cerrar al exterior los servicios no esenciales.

## 8. Lecciones aprendidas

Qué funcionó. La regla disparó con un MTTD de unos 5 minutos y el enriquecimiento GeoIP dio
contexto del origen sin depender de herramientas externas.

Qué mejorar:

- La regla es de coincidencia simple: detecta la cadena `Port scan` en el mensaje, no el
  comportamiento. Una regla threshold (>100 puertos en <10 s agrupando por `alert_ip`) sería
  mucho más resistente a falsos positivos.
- Falta una regla de correlación que encadene Reconocimiento → Acceso Inicial desde la misma
  IP. Habría permitido afirmar que estos escaneos eran independientes sin revisarlo a mano.
- Integrar un feed de Threat Intelligence (MISP, OpenCTI) para priorizar por reputación y no
  solo por firma.
