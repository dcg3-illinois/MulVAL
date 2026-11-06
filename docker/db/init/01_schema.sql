-- ---------------------------------------------------------------------------
-- NVD + EPSS database schema for MulVAL analysis-time CVE lookup
-- ---------------------------------------------------------------------------

CREATE DATABASE IF NOT EXISTS cve;
USE cve;

-- Core NVD CVE record: identifies each vulnerability and its CVSS metrics.
-- 'source' tracks provenance so we can mix snapshots and live API pulls.
CREATE TABLE IF NOT EXISTS cve (
    id             VARCHAR(32)  NOT NULL,          -- e.g. CVE-2010-0483
    description    TEXT,
    published      DATE,
    -- CVSS v2
    v2_base_score  DECIMAL(4,1),
    v2_cvss_vector VARCHAR(255),
    -- CVSS v3.x
    v3_base_score  DECIMAL(4,1),
    v3_cvss_vector VARCHAR(255),
    -- Parsed attack-complexity metric (h / m / l), inferred from vector if set,
    -- otherwise NULL. Stored separately so the analysis layer can map AC -> prob.
    v3_attack_complexity CHAR(1),
    source         VARCHAR(32)  DEFAULT 'snapshot',
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (id)
) ENGINE=InnoDB;

-- EPSS score per CVE. Values are 0..1 decimals; percentile is 0..100.
-- date identifies which snapshot day this row came from.
CREATE TABLE IF NOT EXISTS epss (
    id         VARCHAR(32)  NOT NULL,
    score      DECIMAL(7,5) NOT NULL,      -- e.g. 0.06321
    percentile DECIMAL(7,5),               -- e.g. 71.21300
    date       DATE         NOT NULL,      -- snapshot day (always present)
    PRIMARY KEY (id, date)
) ENGINE=InnoDB;

-- Convenient view: join CVSS AC and EPSS for a CVE.
CREATE OR REPLACE VIEW cve_lookup AS
SELECT
    c.id,
    c.description,
    c.v3_attack_complexity,
    c.v3_base_score,
    c.v2_base_score,
    e.score        AS epss_score,
    e.percentile   AS epss_percentile,
    e.score > 0.1 AS epss_high
FROM cve c
LEFT JOIN (
    SELECT ep.id, ep.score, ep.percentile
    FROM epss ep
    INNER JOIN (
        SELECT id, MAX(date) AS max_date FROM epss GROUP BY id
    ) m ON ep.id = m.id AND ep.date = m.max_date
) e ON c.id = e.id;