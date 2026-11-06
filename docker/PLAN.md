# MulVAL Dockerization + DB-backed CVSS/EPSS Probability Assessment — Plan

## Goal
Build a reproducible, Docker-based MulVAL environment that lets you:

1. Run MulVAL's `graph_gen.sh` and `probAssess.sh` inside a container (no host setup).
2. Put **real CVE IDs** into your input factory (`.P`) files and have MulVAL / `probAssess.sh` pull CVSS / EPSS values from a **local MySQL database at analysis time** — so you don't hard-code scores when authoring inputs.
3. **Swap probability methods per run** (CVSS AC value, EPSS score, etc.) against the *same* generated attack graph.
4. Support **reproducibility**: a committed snapshot of NVD/EPSS data usable offline, *and* an option to refresh from live APIs when available.

## Background findings (from code read)
- `utils/probAssess.sh` → `java independentAlgoSumm` reads `VERTICES.CSV`.
- `src/metrics/independentAlgoSumm.java` (lines ~116–131) currently takes the **last CSV column** as the numeric conditional probability. A `getConnection()` (JDBC, reads `config.txt`) and a commented-out `lookup_ac()` already exist — the authors *intended* DB lookup but left it disabled.
- The valid `convertLetter2Num()` (h/m/l → 0.2/0.6/0.9) mapping is also commented out.
- Input files in this fork use **arbitrary vuln IDs** (e.g. `N1-2010-0483`, `subnet1_host_10_localVul_0`), not necessarily real CVEs — but the convention `vulExists(host,'CVE-...',prog)` + `cvss(VulID, AC)` is supported. For DB lookup, input files must use **real CVE IDs**.
- `config.txt` holds JDBC URL / user / password; the wilbercui image uses `jdbc:mysql://localhost:3306/nvd`, root/root.

## Proposed file layout (all under `docker/` unless noted)
```
Dockerfile                  (repo root — already drafted, may be moved/adjusted)
docker/
  docker-compose.yml        (optional: wire container to a MySQL service)
  db/
    init/
      01_schema.sql         (already created — cve + epss + view)
    loader/
      load_nvd.py           (NVD JSON → DB; supports live API + snapshot file)
      load_epss.py          (FIRST.org EPSS → DB; supports live API + snapshot CSV)
      snapshot/             (committed data snapshots, optional)
    scripts/
      refresh.sh            (startup refresh: load snapshot, optionally pull live)
  metrics/
    config.txt              (JDBC URL / user / password template)
```

## Changes to the codebase
Twelve items below are proposed. Each will be shown as a diff for your approval **before** I create/modify it.

### A. Build / runtime plumbing
1. **`Dockerfile` (root)** — Modernized build (Ubuntu 24.04, OpenJDK 17, XSB 5.0, giper45 PR #9 patch). **Add:** MySQL server, Python3 for loaders, JDBC MySQL connector, start MySQL at runtime. Provide both snapshot import (build/pull) and on-start refresh hooks.
2. **`docker/db/init/01_schema.sql`** — *already written*; holding schema in place.
3. **`docker/docker-compose.yml`** — (optional convenience) to run a separate MySQL service + the analysis container. Will only add if you want a multi-container setup; otherwise the single container runs MySQL itself.

### B. Loaders
4. **`docker/db/loader/load_nvd.py`** — Imports CVE records (CVSS v2/v3 + parsed AC) from a local JSON snapshot file (reproducible) OR the NVD API v2 (live). Upserts into `cve`.
5. **`docker/db/loader/load_epss.py`** — Imports EPSS score/percentile from a local CSV snapshot OR the FIRST.org EPSS API. Upserts into `epss` keyed by `(id, date)`.
6. **`docker/db/scripts/refresh.sh`** — Orchestrates: ensure MySQL up → import snapshot by default → optionally refresh with `--live` flag before running analysis.
7. **`README.md` in `docker/`** — Usage: build, run, mount `/input`, sync CVE data, choose probability method.

### C. Analysis-time lookup (the core feature)
8. **`docker/metrics/config.txt`** — JDBC connection template (defaults matching the container's MySQL).
9. **`src/metrics/independentAlgoSumm.java` (MODIFY)** — Activates DB lookup:
   - Add a `-method` argument (e.g. `cvss-ac` or `epss`) to select the probability source per run.
   - For a `vuln_exists`-style node, extract CVE ID from the graph and query the DB.
   - Map CVSS AC (h/m/l)/EPSS to a numeric conditional probability.
   - Fall back to the numeric column value if no DB value exists (backwards compatible).
   - Add the JDBC driver to classpath in `probAssess.sh`.
10. **`utils/probAssess.sh` (MODIFY)** — Pass the selected method + DB classpath.

### D. Options / knobs
11. **Probability mapper** (implemented inside Java or a small helper): CVSS AC (h=0.2, m=0.6, l=0.9), EPSS raw score, EPSS percentile, plus a pluggable map for other methods later.

## What I will NOT do (unless you ask)
- I will not overwrite the original `interaction_rules*.P` files.
- I will not remove or rename existing repo files.
- I will not change `graph_gen.sh` semantics.

## Decided (confirmed)
1. **Single self-contained container** that runs its own local MySQL (no docker-compose DB service).
2. **Snapshot by default** — committed NVD/EPSS data is loaded at startup; offline-safe.
3. **No live API integration for now** — deferred until a later iteration. The snapshot import path is the only data-loading path for now.
4. CVSS AC mapping uses the classic Wang et al. values (h=0.2, m=0.6, l=0.9), overridable later.

## Deferred (future work, not in this iteration)
- Live NVD API / FIRST.org EPSS API refresh (`--live` flag, `refresh.sh`).
- Building the snapshot files themselves (fetching data). For now we build the loader + loading scripts; snapshot data can be added by the user or in a later step.

## Next step
Proceed with implementation in this order, showing diffs for the existing tracked-file modifications (`independentAlgoSumm.java`, `probAssess.sh`) before writing them:
1. Rewrite `Dockerfile` to add **MySQL** (single-container), Python3, JDBC driver, and snapshot-import startup.
2. `docker/db/loader/load_nvd.py` + `load_epss.py` (snapshot import only for now).
3. `docker/db/scripts/seed.sh` (startup import hook).
4. `docker/metrics/config.txt` + JDBC lib wiring.
5. Modify `independentAlgoSumm.java` + `probAssess.sh` for analysis-time DB lookup.
6. `docker/README.md` usage doc.