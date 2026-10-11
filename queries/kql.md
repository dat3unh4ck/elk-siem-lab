# Consultas KQL — Kibana Discover

Data view: **macOS Logs** (`macos-logs-*`). Campo temporal: `@timestamp`.

## Triaje básico

```
process : "syslogd"
```
Filtra por proceso emisor. Útil para aislar el ruido de un servicio concreto.

```
log_message : "*error*" OR log_message : "*fail*"
```
Barrido de errores y fallos en todo el índice.

```
severidad : "critica"
```
Todo lo clasificado como crítico por la etapa 6 del pipeline de Logstash.
Es la primera consulta de cualquier turno.

## Investigación de una IP

```
alert_ip : "177.72.82.22"
```
Toda la actividad asociada a una IP. Responde a "¿qué más ha hecho?".

```
alert_ip : "177.72.82.22" OR alert_ip : "5.160.218.45"
```
Pivoteo entre varias IPs para distinguir actividad coordinada de oportunista:
si los tiempos se entrelazan, hay coordinación.

## Por técnica

```
log_message : "*Port scan*"
```
```
log_message : "*Failed authentication*"
```
```
log_message : "*Suspicious outbound connection*"
```
```
log_message : "*Unauthorized sudo*"
```
```
log_message : "*Critical file modification*"
```

## Geolocalización

```
geoip.geo.country_name : "China" and severidad : "critica"
```
Cruce de origen geográfico con severidad.

```
alert_ip : * and not geoip.geo.location : *
```
Eventos con IP extraída pero sin resolución GeoIP — normalmente IPs privadas o
reservadas. Sirve para separar el tráfico interno del externo.

## Verificación del pipeline

```
tags : "_grok_parse_failure"
```
Líneas que el Grok de la etapa 1 no supo parsear. Si este número crece, el
pipeline se ha quedado corto ante un formato de log nuevo y hay pérdida de
visibilidad: conviene revisarlo periódicamente.

```
tags : "_geoip_lookup_failure"
```
IPs que el lookup GeoIP no pudo resolver.
