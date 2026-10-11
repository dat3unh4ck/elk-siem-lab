#!/usr/bin/env bash
#
# setup.sh — Configuracion post-despliegue de la pila ELK.
#
# Ejecutar UNA VEZ despues de `docker compose up -d`, cuando Elasticsearch
# este healthy. Es idempotente: se puede relanzar sin romper nada.
#
#   1. Fija la contrasena del usuario de servicio kibana_system.
#   2. Activa la licencia Trial (necesaria para el motor de deteccion SIEM).
#   3. Crea el index template que mapea geoip.geo.location como geo_point.
#   4. Verifica la salud del cluster.
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ES_URL="${ES_URL:-http://localhost:9200}"

if [[ -f "$ROOT/.env" ]]; then
  set -a; source "$ROOT/.env"; set +a
else
  echo "ERROR: no existe $ROOT/.env. Copia .env.example a .env y rellenalo." >&2
  exit 1
fi

: "${ELASTIC_PASSWORD:?falta ELASTIC_PASSWORD en .env}"
: "${KIBANA_SYSTEM_PASSWORD:?falta KIBANA_SYSTEM_PASSWORD en .env}"

es() { curl -fsS -u "elastic:${ELASTIC_PASSWORD}" "$@"; }

echo "==> Esperando a que Elasticsearch responda en ${ES_URL} ..."
for i in {1..40}; do
  if es "${ES_URL}/_cluster/health" >/dev/null 2>&1; then break; fi
  if [[ $i -eq 40 ]]; then
    echo "ERROR: Elasticsearch no responde. Revisa 'docker compose logs elasticsearch'." >&2
    exit 1
  fi
  sleep 5
done

echo "==> 1/4 Fijando la contrasena de kibana_system"
es -X POST "${ES_URL}/_security/user/kibana_system/_password" \
   -H 'Content-Type: application/json' \
   -d "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}" >/dev/null
echo "    hecho"

echo "==> 2/4 Activando licencia Trial (30 dias, desbloquea el Detection Engine)"
es -X POST "${ES_URL}/_license/start_trial?acknowledge=true" >/dev/null 2>&1 \
  && echo "    activada" \
  || echo "    ya estaba activada o no aplica, se continua"

echo "==> 3/4 Creando el index template macos-logs-template"
es -X PUT "${ES_URL}/_index_template/macos-logs-template" \
   -H 'Content-Type: application/json' \
   --data-binary "@${ROOT}/elasticsearch/index-template.json" >/dev/null
echo "    hecho"

echo "==> 4/4 Salud del cluster"
es "${ES_URL}/_cluster/health?pretty"

cat <<'EOF'

Listo. Siguientes pasos manuales en Kibana (http://localhost:5601):

  1. Stack Management -> Data Views -> Create data view
       Name:           macOS Logs
       Index pattern:  macos-logs-*
       Timestamp:      @timestamp

  2. Reinicia Kibana para que tome la nueva contrasena:
       docker compose restart kibana

  3. Carga eventos de prueba:
       ./scripts/inject-test-events.sh

  4. Crea las 5 reglas de deteccion: ver detection-rules/README.md
EOF
