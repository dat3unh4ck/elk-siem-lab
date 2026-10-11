# Reglas de detección — Kibana Security (SIEM)

Cinco reglas custom creadas en **Security → Rules → Detection rules (SIEM)**, cada una
mapeada a su táctica y técnica de MITRE ATT&CK.

Cada regla de este directorio tiene su equivalente portable en [`../sigma-rules/`](../sigma-rules/):
la regla Sigma es la fuente de verdad del detection logic y la de Kibana es su
implementación concreta en este SIEM.

## Cobertura

| Regla | Severidad | Táctica | Técnica | Sigma equivalente |
|---|---|---|---|---|
| Brute Force — Intentos de autenticación fallidos | Critical | Credential Access | [T1110](https://attack.mitre.org/techniques/T1110/) | `brute_force_auth.yml` |
| Escalada de Privilegios — Sudo no autorizado | Critical | Privilege Escalation | [T1548](https://attack.mitre.org/techniques/T1548/) | `privilege_escalation_sudo.yml` |
| Conexión C2 — Comunicación saliente sospechosa | Critical | Command and Control | [T1071](https://attack.mitre.org/techniques/T1071/) | `c2_outbound_connection.yml` |
| Integridad — Modificación de fichero crítico | High | Persistence | [T1098](https://attack.mitre.org/techniques/T1098/) | `critical_file_modification.yml` |
| Reconocimiento — Escaneo de puertos detectado | High | Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | `port_scan_detection.yml` |

## Cómo crearlas

Para cada fila de la tabla anterior:

1. **Security → Rules → Detection rules (SIEM) → Create new rule**
2. Tipo de regla: **Custom query**
3. **Index patterns:** `macos-logs-*`
4. **Custom query:** la consulta Lucene correspondiente (tabla de abajo)
5. **About:** nombre y severidad de la tabla de cobertura
6. **MITRE ATT&CK threats:** añade la táctica y la técnica indicadas
7. **Schedule:** cada 5 minutos, con `Additional look-back time` de 1 minuto

> **Requisito previo:** las tres `encryptionKey` de `kibana.yml` deben estar definidas.
> Sin ellas Kibana rechaza la creación de reglas con el error
> *"Unable to create actions client because the Encrypted Saved Objects plugin is missing encryption key."*

## Consultas

Obtenidas convirtiendo las reglas Sigma con `sigma-cli` (ver el README raíz):

| Regla | Query Lucene |
|---|---|
| Brute Force | `log_message:*Failed authentication*` |
| Escalada de Privilegios | `log_message:*Unauthorized sudo*` |
| Conexión C2 | `log_message:*Suspicious outbound connection*` |
| Integridad de fichero | `log_message:*Critical file modification*` |
| Port Scan | `log_message:*Port scan*` |

## Limitaciones conocidas

Son reglas de coincidencia simple sobre el texto del evento, suficientes para validar
el flujo completo de detección pero no para producción. Mejoras pendientes:

- **Threshold en lugar de match simple.** Una autenticación fallida no es un ataque;
  veinte en un minuto desde la misma IP sí. Las reglas de Brute Force y Port Scan
  deberían ser de tipo `threshold` agrupando por `alert_ip`.
- **Correlación entre fases.** Una regla que encadene Reconocimiento → Acceso Inicial
  desde la misma IP detecta el ataque, no sus piezas sueltas.
- **Enriquecimiento con Threat Intelligence** antes de alertar, para priorizar por
  reputación de la IP en vez de solo por la firma. Primer paso hecho en
  [`../scripts/enrich_ips.py`](../scripts/enrich_ips.py).
