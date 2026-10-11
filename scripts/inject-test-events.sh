#!/usr/bin/env bash
#
# inject-test-events.sh — Inyecta 10 eventos de seguridad simulados en el log
# del sistema para disparar las reglas de deteccion y el enriquecimiento GeoIP.
#
# Las IPs son publicas y reales (de distintos paises) para que el lookup GeoIP
# resuelva y el mapa de Kibana muestre puntos. NO se ataca a ninguna de ellas:
# solo aparecen como texto dentro de una linea de log.
#
# Uso:   sudo ./scripts/inject-test-events.sh
#
set -euo pipefail

LOG_FILE="${LOG_FILE:-/var/log/system.log}"
HOST="${HOSTNAME_TAG:-MacBook-Pro-de-Jonathas}"
STAMP="$(date '+%b %e %H:%M:%S')"

if [[ ! -w "$LOG_FILE" ]]; then
  echo "ERROR: no se puede escribir en $LOG_FILE. Ejecuta con sudo." >&2
  exit 1
fi

cat >> "$LOG_FILE" <<EOF
${STAMP} ${HOST} auth[8801]: ALERT: Failed authentication attempt for user admin from 218.92.0.107
${STAMP} ${HOST} auth[8802]: ALERT: Failed authentication attempt for user root from 218.92.0.107
${STAMP} ${HOST} auth[8803]: ALERT: Failed authentication attempt for user admin from 218.92.0.107
${STAMP} ${HOST} kernel[0]: ALERT: Suspicious outbound connection detected to 185.220.101.34
${STAMP} ${HOST} kernel[0]: ALERT: Suspicious outbound connection detected to 45.155.205.99
${STAMP} ${HOST} kernel[0]: ALERT: Port scan detected from 177.72.82.22 - 500 ports scanned in 5 seconds
${STAMP} ${HOST} kernel[0]: ALERT: Port scan detected from 5.160.218.45 - 300 ports scanned in 2 seconds
${STAMP} ${HOST} sudo[8804]: ALERT: Unauthorized sudo attempt by user guest - connection from 103.75.190.11
${STAMP} ${HOST} auth[8805]: ALERT: Critical file modification detected - /etc/passwd modified from 91.234.99.70
${STAMP} ${HOST} kernel[0]: ALERT: Suspicious outbound connection detected to 194.26.192.64
EOF

cat <<'EOF'
10 eventos inyectados.

Verificalo en Kibana -> Discover con:   log_message : "*ALERT*"

Nota sobre zona horaria: Logstash parsea los timestamps como UTC y Kibana los
muestra en hora local. Si no aparecen, amplia el rango a "Today" o "Last 1 year"
en lugar de "Last 15 minutes".
EOF
