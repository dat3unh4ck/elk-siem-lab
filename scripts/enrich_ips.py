#!/usr/bin/env python3
"""
enrich_ips.py — Enriquecimiento de IPs del SIEM con Threat Intelligence.

Flujo:
  1. Consulta Elasticsearch y extrae las IPs unicas observadas en los logs.
  2. Descarta IPs privadas, de loopback y reservadas (no tienen reputacion publica).
  3. Consulta AbuseIPDB y VirusTotal para cada IP, respetando sus rate limits.
  4. Calcula un veredicto unificado.
  5. Escribe el resultado en el indice de inteligencia (fuente de verdad).
  6. Propaga un resumen a los documentos originales para uso directo en dashboards.

Uso:
    export ABUSEIPDB_API_KEY="..."
    export VT_API_KEY="..."
    export ES_PASSWORD="..."
    python3 enrich_ips.py --dry-run
    python3 enrich_ips.py
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

# --------------------------------------------------------------------------
# Configuracion
# --------------------------------------------------------------------------

ES_URL = os.getenv("ES_URL", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASSWORD = os.getenv("ES_PASSWORD", "")

SOURCE_INDEX = os.getenv("SOURCE_INDEX", "macos-logs-*")
IP_FIELD = os.getenv("IP_FIELD", "alert_ip")
INTEL_INDEX = os.getenv("INTEL_INDEX", "threat-intel-ips")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VT_API_KEY = os.getenv("VT_API_KEY", "")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

# VirusTotal free tier: 4 peticiones/minuto. Dejamos margen.
VT_MIN_INTERVAL = 16.0
# AbuseIPDB free tier: 1.000 comprobaciones/dia, sin limite estricto por minuto.
ABUSEIPDB_MIN_INTERVAL = 1.0

HTTP_TIMEOUT = 20
MAX_RETRIES = 3

log = logging.getLogger("enrich")


# --------------------------------------------------------------------------
# Modelo
# --------------------------------------------------------------------------

@dataclass
class IpIntel:
    """Inteligencia consolidada sobre una direccion IP."""
    ip: str
    observed_count: int = 0
    verdict: str = "unknown"          # malicious | suspicious | clean | unknown
    score: int = 0                    # 0-100, riesgo normalizado
    country: str | None = None
    isp: str | None = None
    usage_type: str | None = None
    is_tor: bool = False
    abuse_confidence: int | None = None
    abuse_reports: int | None = None
    vt_malicious: int | None = None
    vt_suspicious: int | None = None
    vt_harmless: int | None = None
    vt_reputation: int | None = None
    sources: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    enriched_at: str = ""

    def to_document(self) -> dict[str, Any]:
        doc = asdict(self)
        doc["enriched_at"] = self.enriched_at or _now_iso()
        return doc


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fmt_num(value: int | None) -> str:
    """Formatea un valor numerico distinguiendo 'sin dato' de 'cero'.

    Es una distincion critica en threat intelligence: un 0 significa que la
    fuente respondio y no tiene nada contra esa IP; un guion significa que
    no pudimos preguntarle. Confundirlos lleva a dar por limpia una IP que
    en realidad nunca se llego a comprobar.
    """
    return "-" if value is None else str(value)


def fmt_sources(sources: list[str]) -> str:
    """Resume que fuentes respondieron: A=AbuseIPDB, V=VirusTotal."""
    if not sources:
        return "ninguna"
    marcas = []
    if "abuseipdb" in sources:
        marcas.append("A")
    if "virustotal" in sources:
        marcas.append("V")
    return "+".join(marcas)


class RateLimiter:
    """Espaciador simple entre llamadas a una misma API."""

    def __init__(self, min_interval: float) -> None:
        self.min_interval = min_interval
        self._last_call = 0.0

    def wait(self) -> None:
        elapsed = time.monotonic() - self._last_call
        remaining = self.min_interval - elapsed
        if remaining > 0:
            log.debug("Rate limit: esperando %.1fs", remaining)
            time.sleep(remaining)
        self._last_call = time.monotonic()


# --------------------------------------------------------------------------
# Elasticsearch
# --------------------------------------------------------------------------

def es_request(method: str, path: str, payload: dict | None = None) -> dict:
    """Llamada autenticada a la API REST de Elasticsearch."""
    url = f"{ES_URL.rstrip('/')}/{path.lstrip('/')}"
    response = requests.request(
        method,
        url,
        auth=(ES_USER, ES_PASSWORD),
        json=payload,
        headers={"Content-Type": "application/json"},
        timeout=HTTP_TIMEOUT,
    )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Elasticsearch {method} {path} -> {response.status_code}: {response.text[:300]}"
        )
    return response.json()


def ensure_intel_index() -> None:
    """Crea el indice de inteligencia con mapping explicito si no existe.

    El mapping explicito evita que Elasticsearch infiera tipos por su cuenta:
    'ip' como tipo nativo permite busquedas por rango CIDR, y los campos de
    texto van como keyword porque solo se usan para filtrar y agregar.
    """
    url = f"{ES_URL.rstrip('/')}/{INTEL_INDEX}"
    head = requests.head(url, auth=(ES_USER, ES_PASSWORD), timeout=HTTP_TIMEOUT)
    if head.status_code == 200:
        log.info("Indice '%s' ya existe", INTEL_INDEX)
        return

    mapping = {
        "mappings": {
            "properties": {
                "ip": {"type": "ip"},
                "observed_count": {"type": "integer"},
                "verdict": {"type": "keyword"},
                "score": {"type": "integer"},
                "country": {"type": "keyword"},
                "isp": {"type": "keyword"},
                "usage_type": {"type": "keyword"},
                "is_tor": {"type": "boolean"},
                "abuse_confidence": {"type": "integer"},
                "abuse_reports": {"type": "integer"},
                "vt_malicious": {"type": "integer"},
                "vt_suspicious": {"type": "integer"},
                "vt_harmless": {"type": "integer"},
                "vt_reputation": {"type": "integer"},
                "sources": {"type": "keyword"},
                "errors": {"type": "keyword"},
                "enriched_at": {"type": "date"},
            }
        }
    }
    es_request("PUT", INTEL_INDEX, mapping)
    log.info("Indice '%s' creado con mapping explicito", INTEL_INDEX)


def fetch_observed_ips(limit: int = 500) -> dict[str, int]:
    """Devuelve {ip: numero_de_eventos} a partir de una agregacion terms."""
    query = {
        "size": 0,
        "query": {"exists": {"field": IP_FIELD}},
        "aggs": {
            "ips": {
                "terms": {"field": f"{IP_FIELD}.keyword", "size": limit}
            }
        },
    }
    try:
        result = es_request("POST", f"{SOURCE_INDEX}/_search", query)
    except RuntimeError as exc:
        # Si el campo esta mapeado como 'ip' nativo no existe el subcampo .keyword
        log.warning("Agregacion sobre '.keyword' fallida, reintentando sobre el campo base")
        log.debug("%s", exc)
        query["aggs"]["ips"]["terms"]["field"] = IP_FIELD
        result = es_request("POST", f"{SOURCE_INDEX}/_search", query)

    buckets = result["aggregations"]["ips"]["buckets"]
    return {b["key"]: b["doc_count"] for b in buckets}


def load_cached_intel(max_age_days: int) -> set[str]:
    """IPs ya enriquecidas recientemente, para no gastar cuota de API."""
    cutoff = (datetime.now(timezone.utc) - timedelta(days=max_age_days)).isoformat()
    query = {
        "size": 1000,
        "_source": ["ip"],
        "query": {"range": {"enriched_at": {"gte": cutoff}}},
    }
    try:
        result = es_request("POST", f"{INTEL_INDEX}/_search", query)
    except RuntimeError:
        return set()
    return {hit["_source"]["ip"] for hit in result["hits"]["hits"]}


def index_intel(intel: IpIntel) -> None:
    """Escribe el documento de inteligencia usando la IP como _id (idempotente)."""
    es_request("PUT", f"{INTEL_INDEX}/_doc/{intel.ip}?refresh=true", intel.to_document())
    log.info("  -> indexado en %s", INTEL_INDEX)


def propagate_to_source(intel: IpIntel) -> int:
    """Copia un resumen del veredicto a los documentos originales del SIEM.

    Se usa _update_by_query con un script Painless: escribe solo los campos
    resumen bajo 'threat.*' y deja intacto el resto del documento.
    """
    body = {
        "query": {"term": {f"{IP_FIELD}.keyword": intel.ip}},
        "script": {
            "source": (
                "if (ctx._source.threat == null) { ctx._source.threat = [:]; } "
                "ctx._source.threat.verdict = params.verdict; "
                "ctx._source.threat.score = params.score; "
                "ctx._source.threat.abuse_confidence = params.abuse; "
                "ctx._source.threat.vt_malicious = params.vt; "
                "ctx._source.threat.enriched_at = params.ts;"
            ),
            "lang": "painless",
            "params": {
                "verdict": intel.verdict,
                "score": intel.score,
                "abuse": intel.abuse_confidence,
                "vt": intel.vt_malicious,
                "ts": intel.enriched_at or _now_iso(),
            },
        },
    }
    try:
        result = es_request("POST", f"{SOURCE_INDEX}/_update_by_query?refresh=true", body)
    except RuntimeError:
        body["query"] = {"term": {IP_FIELD: intel.ip}}
        result = es_request("POST", f"{SOURCE_INDEX}/_update_by_query?refresh=true", body)
    updated = result.get("updated", 0)
    log.info("  -> %d documentos originales actualizados", updated)
    return updated


# --------------------------------------------------------------------------
# Proveedores de Threat Intelligence
# --------------------------------------------------------------------------

def _get_with_retries(url: str, headers: dict, params: dict | None = None) -> requests.Response | None:
    """GET con reintentos y respeto al 429 (Too Many Requests)."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(url, headers=headers, params=params, timeout=HTTP_TIMEOUT)
        except requests.RequestException as exc:
            log.warning("  error de red (intento %d/%d): %s", attempt, MAX_RETRIES, exc)
            time.sleep(2 * attempt)
            continue

        if response.status_code == 429:
            espera = 30 * attempt
            log.warning("  rate limit alcanzado, esperando %ds", espera)
            time.sleep(espera)
            continue
        return response
    return None


def query_abuseipdb(ip: str, limiter: RateLimiter) -> dict[str, Any]:
    if not ABUSEIPDB_API_KEY:
        return {"error": "ABUSEIPDB_API_KEY no configurada"}

    limiter.wait()
    response = _get_with_retries(
        ABUSEIPDB_URL,
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
    )
    if response is None:
        return {"error": "sin respuesta tras reintentos"}
    if response.status_code != 200:
        return {"error": f"HTTP {response.status_code}"}

    data = response.json().get("data", {})
    return {
        "abuse_confidence": data.get("abuseConfidenceScore"),
        "abuse_reports": data.get("totalReports"),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "usage_type": data.get("usageType"),
        "is_tor": bool(data.get("isTor", False)),
    }


def query_virustotal(ip: str, limiter: RateLimiter) -> dict[str, Any]:
    if not VT_API_KEY:
        return {"error": "VT_API_KEY no configurada"}

    limiter.wait()
    response = _get_with_retries(
        VT_URL.format(ip=ip),
        headers={"x-apikey": VT_API_KEY, "Accept": "application/json"},
    )
    if response is None:
        return {"error": "sin respuesta tras reintentos"}
    if response.status_code == 404:
        return {"error": "IP no encontrada en VirusTotal"}
    if response.status_code != 200:
        return {"error": f"HTTP {response.status_code}"}

    attributes = response.json().get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    return {
        "vt_malicious": stats.get("malicious"),
        "vt_suspicious": stats.get("suspicious"),
        "vt_harmless": stats.get("harmless"),
        "vt_reputation": attributes.get("reputation"),
        "country": attributes.get("country"),
    }


# --------------------------------------------------------------------------
# Logica de veredicto
# --------------------------------------------------------------------------

def compute_verdict(intel: IpIntel) -> None:
    """Combina ambas fuentes en un unico veredicto y una puntuacion 0-100.

    Criterio deliberadamente conservador: una sola fuente marcando la IP como
    maliciosa basta para elevar el veredicto, porque en triaje es preferible
    revisar un falso positivo que ignorar un verdadero positivo.
    """
    abuse = intel.abuse_confidence or 0
    vt_mal = intel.vt_malicious or 0
    vt_susp = intel.vt_suspicious or 0

    # La puntuacion de VirusTotal se normaliza: 5+ motores marcando = 100.
    vt_score = min(vt_mal * 20, 100)
    intel.score = max(abuse, vt_score)

    if not intel.sources:
        intel.verdict = "unknown"
    elif abuse >= 50 or vt_mal >= 3:
        intel.verdict = "malicious"
    elif abuse >= 25 or vt_mal >= 1 or vt_susp >= 2 or intel.is_tor:
        intel.verdict = "suspicious"
    else:
        intel.verdict = "clean"


def is_public_ip(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        address.is_private
        or address.is_loopback
        or address.is_reserved
        or address.is_multicast
        or address.is_link_local
    )


# --------------------------------------------------------------------------
# Orquestacion
# --------------------------------------------------------------------------

def enrich_ip(ip: str, observed: int, abuse_limiter: RateLimiter, vt_limiter: RateLimiter) -> IpIntel:
    intel = IpIntel(ip=ip, observed_count=observed)

    abuse_data = query_abuseipdb(ip, abuse_limiter)
    if "error" in abuse_data:
        intel.errors.append(f"abuseipdb: {abuse_data['error']}")
    else:
        intel.sources.append("abuseipdb")
        for key, value in abuse_data.items():
            setattr(intel, key, value)

    vt_data = query_virustotal(ip, vt_limiter)
    if "error" in vt_data:
        intel.errors.append(f"virustotal: {vt_data['error']}")
    else:
        intel.sources.append("virustotal")
        for key, value in vt_data.items():
            if key == "country" and intel.country:
                continue  # no pisamos el dato de AbuseIPDB
            setattr(intel, key, value)

    intel.enriched_at = _now_iso()
    compute_verdict(intel)
    return intel


def main() -> int:
    parser = argparse.ArgumentParser(description="Enriquece IPs del SIEM con Threat Intelligence")
    parser.add_argument("--dry-run", action="store_true",
                        help="consulta las APIs pero no escribe en Elasticsearch")
    parser.add_argument("--force", action="store_true",
                        help="reconsulta IPs ya enriquecidas recientemente")
    parser.add_argument("--max-age-days", type=int, default=7,
                        help="antiguedad tolerada de la cache (por defecto 7 dias)")
    parser.add_argument("--no-propagate", action="store_true",
                        help="no actualiza los documentos originales")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )

    if not ES_PASSWORD:
        log.error("Falta ES_PASSWORD. Exportala antes de ejecutar.")
        return 1
    if not ABUSEIPDB_API_KEY and not VT_API_KEY:
        log.error("No hay ninguna API key configurada (ABUSEIPDB_API_KEY / VT_API_KEY).")
        return 1

    try:
        health = es_request("GET", "_cluster/health")
        log.info("Elasticsearch '%s' en estado %s", health["cluster_name"], health["status"])
    except Exception as exc:
        log.error("No se pudo contactar con Elasticsearch: %s", exc)
        return 1

    if not args.dry_run:
        ensure_intel_index()

    observed = fetch_observed_ips()
    log.info("IPs observadas en %s: %d", SOURCE_INDEX, len(observed))

    candidates = {ip: count for ip, count in observed.items() if is_public_ip(ip)}
    descartadas = len(observed) - len(candidates)
    if descartadas:
        log.info("Descartadas %d IPs privadas o reservadas", descartadas)

    if not args.force and not args.dry_run:
        cached = load_cached_intel(args.max_age_days)
        antes = len(candidates)
        candidates = {ip: c for ip, c in candidates.items() if ip not in cached}
        if antes != len(candidates):
            log.info("Omitidas %d IPs ya enriquecidas (usa --force para rehacerlas)",
                     antes - len(candidates))

    if not candidates:
        log.info("No hay nada que enriquecer.")
        return 0

    estimado = len(candidates) * VT_MIN_INTERVAL / 60
    log.info("A enriquecer: %d IPs (~%.1f min por el rate limit de VirusTotal)",
             len(candidates), estimado)

    abuse_limiter = RateLimiter(ABUSEIPDB_MIN_INTERVAL)
    vt_limiter = RateLimiter(VT_MIN_INTERVAL)

    resumen: list[IpIntel] = []
    orden = sorted(candidates.items(), key=lambda kv: kv[1], reverse=True)

    for posicion, (ip, count) in enumerate(orden, start=1):
        log.info("[%d/%d] %s  (%d eventos)", posicion, len(orden), ip, count)
        intel = enrich_ip(ip, count, abuse_limiter, vt_limiter)
        log.info("  veredicto=%s score=%d abuse=%s vt_malicious=%s fuentes=%s",
                 intel.verdict, intel.score, fmt_num(intel.abuse_confidence),
                 fmt_num(intel.vt_malicious), fmt_sources(intel.sources))
        for err in intel.errors:
            log.warning("  %s", err)

        if not args.dry_run:
            index_intel(intel)
            if not args.no_propagate:
                propagate_to_source(intel)

        resumen.append(intel)

    print("\n" + "=" * 72)
    print(f"{'IP':<18}{'VEREDICTO':<13}{'SCORE':>6}{'ABUSE':>7}{'VT':>5}"
          f"{'FUENTES':>9}  PAIS  ISP")
    print("=" * 72)
    for intel in sorted(resumen, key=lambda i: i.score, reverse=True):
        print(f"{intel.ip:<18}{intel.verdict:<13}{intel.score:>6}"
              f"{fmt_num(intel.abuse_confidence):>7}{fmt_num(intel.vt_malicious):>5}"
              f"{fmt_sources(intel.sources):>9}"
              f"  {intel.country or '--':<5} {(intel.isp or '')[:28]}")
    print("=" * 72)

    maliciosas = sum(1 for i in resumen if i.verdict == "malicious")
    sospechosas = sum(1 for i in resumen if i.verdict == "suspicious")
    print(f"Total: {len(resumen)}  |  Maliciosas: {maliciosas}  |  Sospechosas: {sospechosas}")

    parciales = [i for i in resumen if len(i.sources) < 2]
    if parciales:
        print(f"\nAVISO: {len(parciales)} IP(s) evaluadas sin respuesta de todas las fuentes.")
        for i in parciales:
            print(f"  {i.ip:<18} fuentes={fmt_sources(i.sources)}  {'; '.join(i.errors)}")
    if args.dry_run:
        print("\n(dry-run: no se ha escrito nada en Elasticsearch)")

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log.warning("Interrumpido por el usuario")
        sys.exit(130)
