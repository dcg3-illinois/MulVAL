#!/usr/bin/env python3
"""Import a committed FIRST.org EPSS snapshot (CSV) into the local MySQL DB.

Accepts either:
  * The FIRST.org EPSS CSV bundle format (remote `epss` table): columns
    `model, date, cve, epss, percentile`, OR
  * A simple `cve,score,percentile[,date]` CSV with a header row.

This is a pure snapshot loader (offline). Live-API refresh is intentionally
deferred (per PLAN.md).
"""

import argparse
import csv
import datetime
import sys

try:
    import pymysql
except ImportError:
    pymysql = None


def _connect(url, user, password):
    if pymysql is None:
        raise RuntimeError("pymysql is required; install with: pip install pymysql")
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


def load(cursor, path, force_date=None):
    n = 0
    default_date = datetime.date.today().isoformat()
    with open(path, "r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader, None)
        # Normalize header columns to lower-case for detection.
        cols = [h.strip().lower() for h in header] if header else []
        for row in reader:
            if not row:
                continue
            record = dict(zip(cols, row))
            # FIRST.org bundle: model,date,cve,epss,percentile
            cve = record.get("cve")
            if not cve:
                continue
            date = force_date or record.get("date") or default_date
            score = record.get("epss") or record.get("score")
            percentile = record.get("percentile")
            if score is None:
                continue
            cursor.execute(
                """
                INSERT INTO epss (id, score, percentile, date)
                VALUES (%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    score=VALUES(score),
                    percentile=VALUES(percentile)
                """,
                (cve, score, percentile, date),
            )
            n += 1
    print(f"[load_epss] imported {n} EPSS records.")


def main():
    ap = argparse.ArgumentParser(description="Import EPSS snapshot into MySQL")
    ap.add_argument("--file", required=True, help="Path to EPSS CSV snapshot")
    ap.add_argument("--url", default="jdbc:mysql://localhost:3306/cve")
    ap.add_argument("--user", default="root")
    ap.add_argument("--password", default="root")
    ap.add_argument("--date", default=None, help="Optionally override the date")
    args = ap.parse_args()

    conn = _connect(args.url, args.user, args.password)
    try:
        with conn.cursor() as cur:
            load(cur, args.file, force_date=args.date)
    finally:
        conn.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001
        print(f"[load_epss] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)