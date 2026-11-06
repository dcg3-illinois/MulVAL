#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Idempotent snapshot import into the local MySQL DB.
# Loads the committed NVD + EPSS snapshots from docker/db/loader/snapshot/.
#
# Snapshot files referenced here should live in the git repo under:
#   docker/db/loader/snapshot/nvd.json
#   docker/db/loader/snapshot/epss.csv
#
# If a snapshot file is absent, the loader is skipped gracefully so the
# container still boots. (Future: add live-API refresh behind a --live flag.)
# ---------------------------------------------------------------------------
set -euo pipefail

DB_URL="jdbc:mysql://localhost:3306/cve"
DB_USER="root"
DB_PASS="root"

SNAP_DIR="${MULVAL_CVE_SNAPSHOT_DIR:-/opt/mulval-cve/loader/snapshot}"

# Guard against loading when a snapshot dir literally has no data yet.
if [ ! -d "$SNAP_DIR" ]; then
    echo "[seed] No snapshot directory at $SNAP_DIR; skipping snapshot import."
    exit 0
fi

if [ -f "$SNAP_DIR/nvd.json" ]; then
    echo "[seed] Importing NVD snapshot: $SNAP_DIR/nvd.json"
    python3 /opt/mulval-cve/loader/load_nvd.py \
        --file "$SNAP_DIR/nvd.json" \
        --url "$DB_URL" --user "$DB_USER" --password "$DB_PASS"
else
    echo "[seed] No nvd.json found; skipping NVD import."
fi

if [ -f "$SNAP_DIR/epss.csv" ]; then
    echo "[seed] Importing EPSS snapshot: $SNAP_DIR/epss.csv"
    python3 /opt/mulval-cve/loader/load_epss.py \
        --file "$SNAP_DIR/epss.csv" \
        --url "$DB_URL" --user "$DB_USER" --password "$DB_PASS"
else
    echo "[seed] No epss.csv found; skipping EPSS import."
fi

echo "[seed] Snapshot import complete."