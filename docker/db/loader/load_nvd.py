#!/usr/bin/env python3
"""Import a committed NVDS snapshot (JSON) into the local MulVAL CVE database.

The snapshot is expected to match the NVD CVE API v2 JSON shape, i.e. a
container like::

    {
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2010-0483",
            "published": "...",
            "descriptions": [ {"lang": "en", "value": "..."} ],
            "metrics": {
              "cvssMetricV31": [ {"cvssData": {"baseScore":..., "cvssData": {...}} }],
              "cvssMetricV2":  [ {"cvssData": {"baseScore":..., "accessVector":...} }]
            }
          }
        }, ...
      ]
    }

This is a pure snapshot loader (offline). Live-API refresh is intentionally
deferred (per PLAN.md).
"""

import argparse
import json
import sys
from urllib.parse import urlparse

try:
    import pymysql
except ImportError:
    pymysql = None


def _connect(url, user, password):
    """Parse a JDBC-style URL into pymysql kwargs."""
    if pymysql is None:
        raise RuntimeError("pymysql is required; install with: pip install pymysql")
    # jdbc:mysql://host:port/db
    netloc = url.split("://", 1)[1]
    hostport, _, db = netloc.partition("/")
    host, _, port = hostport.partition(":")
    return pymysql.connect(
        host=host or "localhost",
        port=int(port) if port else 3306,
        user=user,
        password=password,
        database=db or "cve",
        autocommit=True,
    )


def _parse_ac(v3_vector):
    """Extract attack-complexity letter (H/M/L) from a CVSS v3 vector string."""
    if not v3_vector:
        return None
    for part in v3_vector.split("/"):
        if part.startswith("AC:"):
            return part[3:].lower()[:1]
    return None


def load(cursor, path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    vulns = data.get("vulnerabilities", data if isinstance(data, list) else [])
    n = 0
    for entry in vulns:
        cve = entry.get("cve", entry)
        cve_id = cve.get("id")
        if not cve_id:
            continue

        desc = None
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value")
                break

        published = cve.get("published")
        if published:
            published = published[:10]  # keep YYYY-MM-DD

        metrics = cve.get("metrics", {})
        v3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [{}])[0]
        v2 = (metrics.get("cvssMetricV2") or [{}])[0]

        v3_data = v3.get("cvssData", {}) if v3 else {}
        v2_data = v2.get("cvssData", {}) if v2 else {}

        v3_vector = v3_data.get("vectorString")
        v2_vector = v2_data.get("vectorString")

        cursor.execute(
            """
            INSERT INTO cve
                (id, description, published,
                 v2_base_score, v2_cvss_vector,
                 v3_base_score, v3_cvss_vector, v3_attack_complexity,
                 source)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                description=VALUES(description),
                published=VALUES(published),
                v2_base_score=VALUES(v2_base_score),
                v2_cvss_vector=VALUES(v2_cvss_vector),
                v3_base_score=VALUES(v3_base_score),
                v3_cvss_vector=VALUES(v3_cvss_vector),
                v3_attack_complexity=VALUES(v3_attack_complexity),
                source='snapshot'
            """,
            (
                cve_id,
                desc,
                published,
                v2_data.get("baseScore"),
                v2_vector,
                v3_data.get("baseScore"),
                v3_vector,
                _parse_ac(v3_vector),
            ),
        )
        n += 1
    print(f"[load_nvd] imported {n} CVE records.")


def main():
    ap = argparse.ArgumentParser(description="Import NVD snapshot into MySQL")
    ap.add_argument("--file", required=True, help="Path to NVD JSON snapshot")
    ap.add_argument("--url", default="jdbc:mysql://localhost:3306/cve")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="root")
    args = ap.parse_args()

    conn = _connect(args.url, args.user, args.password)
    try:
        with conn.cursor() as cur:
            load(cur, args.file)
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"[load_nvd] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)