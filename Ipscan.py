#!/usr/bin/env python3

# Usage
# Installer le package request
# Definir les variables d'environment avec export.


from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

import requests
import socket

#Configuration

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VT_API_KEY = os.getenv("VT_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
IPQS_API_KEY = os.getenv("IPQS_API_KEY")


REQUEST_TIMEOUT = 10  # secondes
DELAY_BETWEEN_REQUESTS = 1.0  # pour respecter les rate limits gratuits


# Structure de résultat unifiée


@dataclass
class IPReport:
    ip: str
    source: str
    score: Optional[str] = None          # score / catégorie de risque
    reports_count: Optional[int] = None  # nb de signalements
    country: Optional[str] = None
    isp: Optional[str] = None
    last_seen: Optional[str] = None # dernière analyse / dernier signalement connu
    is_malicious: Optional[bool] = None
    raw_error: Optional[str] = None
    extra: dict = field(default_factory=dict)


# Utilitaires

def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def resolve_domain(domain:str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def humanize_timestamp(raw: Optional[str | int]) -> Optional[str]:
    """Convertit un timestamp Unix ou une chaîne ISO en format lisible."""
    if raw is None:
        return None
    try:
        if isinstance(raw, (int, float)) or str(raw).isdigit():
            dt = datetime.fromtimestamp(int(raw), tz=timezone.utc)
        else:
            dt = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, OSError, OverflowError):
        return str(raw)


# AbuseIPDB


def check_abuseipdb(ip: str) -> IPReport:
    report = IPReport(ip=ip, source="AbuseIPDB")

    if not ABUSEIPDB_API_KEY:
        report.raw_error = "Clé API absente (ABUSEIPDB_API_KEY)"
        return report

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": "true"}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json().get("data", {})

        score = data.get("abuseConfidenceScore")
        report.score = f"{score}/100" if score is not None else None
        report.reports_count = data.get("totalReports")
        report.country = data.get("countryCode")
        report.isp = data.get("isp")
        report.is_malicious = bool(score and score >= 25)
        report.last_seen = humanize_timestamp(data.get("lastReportedAt"))
        report.extra = {
            "usageType": data.get("usageType"),
            "domain": data.get("domain"),
            "isTor": data.get("isTor"),
        }

    except requests.exceptions.HTTPError as e:
        report.raw_error = f"Erreur HTTP {resp.status_code} : {e}"
    except requests.exceptions.RequestException as e:
        report.raw_error = f"Erreur réseau : {e}"

    return report

# VirusTotal

def check_virustotal(ip: str) -> IPReport:
    report = IPReport(ip=ip, source="VirusTotal")

    if not VT_API_KEY:
        report.raw_error = "Clé API absente (VT_API_KEY)"
        return report

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json().get("data", {}).get("attributes", {})

        stats = data.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        report.score = f"{malicious} malveillant(s) / {suspicious} suspect(s) sur {total} moteurs"
        report.country = data.get("country")
        report.isp = data.get("as_owner")
        report.is_malicious = malicious > 0
        report.last_seen = humanize_timestamp(data.get("last_analysis_date"))
        report.extra = {
            "reputation": data.get("reputation"),
            "asn": data.get("asn"),
        }

    except requests.exceptions.HTTPError as e:
        report.raw_error = f"Erreur HTTP {resp.status_code} : {e}"
    except requests.exceptions.RequestException as e:
        report.raw_error = f"Erreur réseau : {e}"

    return report

# VaultOTX


def check_otx(ip: str) -> IPReport:
    report = IPReport(ip=ip, source="AlienVault OTX")

    if not OTX_API_KEY:
        report.raw_error = "Clé API absente (OTX_API_KEY)"
        return report

    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": OTX_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        pulse_count = data.get("pulse_info", {}).get("count", 0)
        report.score = f"{pulse_count} pulse(s) de menace"
        report.reports_count = pulse_count
        report.country = data.get("country_name")
        report.is_malicious = pulse_count > 0
        report.extra = {"tags": data.get("pulse_info", {}).get("tags", [])}

    except requests.exceptions.HTTPError as e:
        report.raw_error = f"Erreur HTTP {resp.status_code} : {e}"
    except requests.exceptions.RequestException as e:
        report.raw_error = f"Erreur réseau : {e}"

    return report


# IPQualityScore


def check_ipqs(ip: str) -> IPReport:
    report = IPReport(ip=ip, source="IPQualityScore")

    if not IPQS_API_KEY:
        report.raw_error = "Clé API absente (IPQS_API_KEY)"
        return report

    url = f"https://ipqualityscore.com/api/json/ip/{IPQS_API_KEY}/{ip}"

    try:
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()

        if not data.get("success", False):
            report.raw_error = data.get("message", "Échec de la requête IPQS")
            return report

        fraud_score = data.get("fraud_score")
        report.score = f"{fraud_score}/100 (fraud score)" if fraud_score is not None else None
        report.country = data.get("country_code")
        report.isp = data.get("ISP")
        report.is_malicious = bool(data.get("malware") or data.get("phishing") or (fraud_score or 0) >= 75)
        # IPQS ne fournit pas toujours une date exacte de dernière analyse
        report.last_seen = None
        report.extra = {
            "vpn": data.get("vpn"),
            "tor": data.get("tor"),
            "proxy": data.get("proxy"),
            "recent_abuse": data.get("recent_abuse"),
        }

    except requests.exceptions.HTTPError as e:
        report.raw_error = f"Erreur HTTP {resp.status_code} : {e}"
    except requests.exceptions.RequestException as e:
        report.raw_error = f"Erreur réseau : {e}"

    return report

# Orchestration


CHECKERS = [check_abuseipdb, check_virustotal, check_otx, check_ipqs]


def analyze_ip(ip: str) -> list[IPReport]:
    results = []
    for checker in CHECKERS:
        results.append(checker(ip))
        time.sleep(DELAY_BETWEEN_REQUESTS)
    return results


def print_human_readable(ip: str, reports: list[IPReport]) -> None:
    print(f"\n{'=' * 60}")
    print(f" IP analysée : {ip}")
    print(f"{'=' * 60}")

    for r in reports:
        print(f"\n--- {r.source} ---")
        if r.raw_error:
            print(f"  ⚠ {r.raw_error}")
            continue

        malicious_flag = "🔴 SUSPECTE" if r.is_malicious else "🟢 propre"
        print(f"  Statut          : {malicious_flag}")
        if r.score is not None:
            print(f"  Score           : {r.score}")
        if r.reports_count is not None:
            print(f"  Signalements    : {r.reports_count}")
        if r.country:
            print(f"  Pays            : {r.country}")
        if r.isp:
            print(f"  FAI / ASN       : {r.isp}")
        if r.last_seen:
            print(f"  Dernière analyse: {r.last_seen}")
        for k, v in r.extra.items():
            if v not in (None, "", False):
                print(f"  {k:<16}: {v}")


def load_ips_from_file(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]



# Point d'entrée CLI


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyse la réputation d'adresses IP via AbuseIPDB, VirusTotal et IPQualityScore."
    )
    parser.add_argument("ips", nargs="*", help="Une ou plusieurs adresses IP à analyser")
    parser.add_argument("--file", "-f", help="Fichier texte contenant une IP par ligne")
    parser.add_argument("--json", action="store_true", help="Sortie au format JSON plutôt que texte")

    args = parser.parse_args()

    ip_list = list(args.ips)
    if args.file:
        ip_list.extend(load_ips_from_file(args.file))

    if not ip_list:
        parser.error("Fournissez au moins une adresse IP (en argument ou via --file).")

    resolved_ip_list = []
    for item in ip_list:
        if is_valid_ip(item):
            resolved_ip_list.append(item)
            continue

        resolved = resolve_domain(item)
        if resolved:
            print(f"✔️​ {item} -> résolu en {resolved}")
            resolved_ip_list.append(resolved)
        else:
            print(f"❌​ Impossible de resoudre: {item}", file=sys.stderr)
    ip_list = resolved_ip_list

    valid_ips = [ip for ip in ip_list if is_valid_ip(ip)]
    invalid_ips = set(ip_list) - set(valid_ips)
    for bad_ip in invalid_ips:
        print(f"⚠ Adresse IP invalide ignorée : {bad_ip}", file=sys.stderr)

    if not any([ABUSEIPDB_API_KEY, VT_API_KEY, IPQS_API_KEY]):
        print(
            "⚠ Aucune clé API détectée. Configurez au moins une des variables "
            "d'environnement : ABUSEIPDB_API_KEY, VT_API_KEY, IPQS_API_KEY.",
            file=sys.stderr,
        )

    all_results = {}
    for ip in valid_ips:
        all_results[ip] = analyze_ip(ip)

    if args.json:
        json_output = {
            ip: [asdict(r) for r in reports] for ip, reports in all_results.items()
        }
        print(json.dumps(json_output, indent=2, ensure_ascii=False))
    else:
        for ip, reports in all_results.items():
            print_human_readable(ip, reports)


if __name__ == "__main__":
    main()









