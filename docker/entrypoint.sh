#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# MulVAL container entrypoint: start local MySQL, import snapshots (idempotent),
# then exec the requested command (default: an interactive bash shell).
# ---------------------------------------------------------------------------
set -e

# 1. Start the bundled MySQL server.
echo "[entrypoint] Starting MySQL..."
service mysql start 2>/dev/null || mysqld_safe &
# Wait for MySQL to accept connections.
for i in $(seq 1 30); do
    if mysqladmin ping --silent 2>/dev/null; then
        break
    fi
    sleep 1
done
mysqladmin ping --silent 2>/dev/null
echo "[entrypoint] MySQL is up."

# 2. Apply schema if needed (idempotent via IF NOT EXISTS).
echo "[entrypoint] Ensuring schema..."
mysql -u root < /opt/mulval-cve/db-init/01_schema.sql

# 3. Seed the CVSS/EPSS snapshot data (idempotent).
if [ -f /opt/mulval-cve/scripts/seed.sh ]; then
    echo "[entrypoint] Seeding snapshot data..."
    bash /opt/mulval-cve/scripts/seed.sh
fi

# 4. Run whatever command the user provided (defaults to bash via CMD).
echo "[entrypoint] Ready. Running: $*"
exec "$@"