# ---------------------------------------------------------------------------
# MulVAL (dcg3-illinois fork) + XSB logic engine + local MySQL (CVSS/EPSS)
# inside a single self-contained container.
#
# Build procedure based on the modern (2023) setup at:
#   https://kazumi.blog/posts/2023/07/how-to-setup-mulval/
#
# Differences vs. the legacy wilbercui/mulval image (Ubuntu 15.04 / XSB 3.6):
#   * Modern Ubuntu 24.04 LTS with OpenJDK 17
#   * XSB 5.0 "Green Tea" from a still-live SourceForge URL
#   * giper45's PR #9 patch applied so the 2015-era source compiles on modern glibc
#   * Bundles a local MySQL instance (single container) preloaded with a
#     committed NVD/EPSS snapshot, so CVSS/EPSS lookup works offline.
#
# Loads CVSS (AC, scores) and EPSS (score, percentile) from the DB at
# analysis time (via the modified independentAlgoSumm.java), rather than
# hard-coding them into input files.
#
# License: GPL-3.0 (see repository LICENSE)
# ---------------------------------------------------------------------------

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# ---------------------------------------------------------------------------
# 1. Base packages: build toolchain + runtime deps + Python for loaders
# ---------------------------------------------------------------------------
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        build-essential \
        default-jdk \
        flex \
        bison \
        graphviz \
        texlive-font-utils \
        xutils-dev \
        git \
        wget \
        ca-certificates \
        curl \
        # Python for the snapshot loader scripts
        python3 \
        python3-pip \
        # MySQL server (single-container DB) + client
        mysql-server \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# 2. Install XSB logic engine from the modern SourceForge release
# ---------------------------------------------------------------------------
ARG XSB_DIR=xsb-5.0.0

WORKDIR /opt
RUN wget -q "https://sourceforge.net/projects/xsb/files/xsb/5.0%20%28Green%20Tea%29/XSB-5.0.tar.gz/download" -O - \
    | tar -xz -C /opt \
    && mv /opt/XSB /opt/${XSB_DIR}

# XSB 5.0 sources keep the build scripts under <root>/build/. Build from there.
WORKDIR /opt/${XSB_DIR}/build
RUN ./configure --prefix=/opt \
    && ./makexsb

ENV XSB_DIR=${XSB_DIR}
WORKDIR /

# ---------------------------------------------------------------------------
# 3. Clone the MulVAL source, apply the modern-compat patch, and build it
# ---------------------------------------------------------------------------
ENV MULVALROOT=/opt/mulval

RUN git clone https://github.com/dcg3-illinois/MulVAL.git ${MULVALROOT}

WORKDIR ${MULVALROOT}

# Apply the giper45 patch (risksense/mulval PR #9) so the 2015-era source
# compiles on modern glibc/g++/bison. The full patch also touches README.md and
# .gitignore which differ in this fork, so scope it to the essential source dir
# (src/attack_graph) to avoid a whole-patch abort. Whitespace warnings are
# expected here and harmless.
RUN wget -q "https://patch-diff.githubusercontent.com/raw/risksense/mulval/pull/9.patch" -O /tmp/mulval-fix.patch \
    && git apply --whitespace=nowarn --include='src/attack_graph/*' /tmp/mulval-fix.patch \
    && rm -f /tmp/mulval-fix.patch

# Compile MulVAL: builds adapter, attack_graph, and the metrics classes
# (including those used by utils/probAssess.sh). The Makefiles copy their
# outputs into bin/{adapter,metrics} but rely on those dirs already existing.
RUN mkdir -p bin/adapter bin/metrics \
    && make

# ---------------------------------------------------------------------------
# 4. Copy repo-local Docker assets (schema, loaders, seed script, JDBC config)
#    into the image. These live in the git repo under docker/.
# ---------------------------------------------------------------------------
COPY docker/db/init/  /opt/mulval-cve/db-init/
COPY docker/db/loader/ /opt/mulval-cve/loader/
COPY docker/db/scripts/ /opt/mulval-cve/scripts/
COPY docker/metrics/config.txt /opt/mulval-cve/config.txt

# Install Python deps needed by the snapshot loaders. Ubuntu 24.04 is
# PEP-668 "externally managed", so --break-system-packages is required here
# (safe within an isolated container).
RUN pip3 install --no-cache-dir --break-system-packages -r /opt/mulval-cve/loader/requirements.txt \
    || true

# Install the MySQL JDBC driver into the MulVAL metrics classpath.
ENV JDBC_JAR=/opt/mulval-cve/mysql-connector-j.jar
RUN curl -fsSL -o "$JDBC_JAR" \
    "https://repo1.maven.org/maven2/com/mysql/mysql-connector-j/8.4.0/mysql-connector-j-8.4.0.jar" \
    || true

# ---------------------------------------------------------------------------
# 5. Runtime: start MySQL, import (seeded) snapshots, drop into a shell.
# ---------------------------------------------------------------------------
WORKDIR /opt/mulval-cve
COPY docker/entrypoint.sh /opt/mulval-cve/entrypoint.sh
RUN chmod +x /opt/mulval-cve/entrypoint.sh /opt/mulval-cve/scripts/*.sh

ENV PATH="${MULVALROOT}/bin:${MULVALROOT}/utils:/opt/${XSB_DIR}/bin:${PATH}"
ENV CLASSPATH="${MULVALROOT}/bin/metrics:${JDBC_JAR}"

# Working-directory convention: mount your input data here and run the scripts.
WORKDIR /input
VOLUME /input

ENTRYPOINT ["/opt/mulval-cve/entrypoint.sh"]
CMD ["bash"]