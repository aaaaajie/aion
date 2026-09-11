# syntax=docker/dockerfile:1

FROM debian:trixie-slim AS radare2-build

ARG RADARE2_VERSION=6.0.4

RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        ca-certificates \
        build-essential \
        git \
        libcapstone-dev \
        libmagic-dev \
        libssl-dev \
        libzip-dev \
        pkg-config \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth 1 --branch "${RADARE2_VERSION}" https://github.com/radareorg/radare2.git /tmp/radare2

WORKDIR /tmp/radare2
RUN ./sys/install.sh /opt/radare2
RUN mkdir -p /opt/radare2/lib-runtime /opt/radare2/share/radare2-runtime \
    && tar --dereference --ignore-failed-read \
        -C /opt/radare2/lib -cf - . \
        | tar -C /opt/radare2/lib-runtime -xf - \
    && tar --dereference --ignore-failed-read \
        -C /opt/radare2/share/radare2 -cf - . \
        | tar -C /opt/radare2/share/radare2-runtime -xf -

FROM python:3.11-slim-trixie

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/opt/aion/tools/binaries/playwright-browsers \
    SEMGREP_SEND_METRICS=off \
    SEMGREP_ENABLE_VERSION_CHECK=0 \
    PYTHONPATH=/opt/aion \
    AION_TOOLCHAIN_ROOT=/opt/aion/tools/binaries \
    PATH=/opt/aion/tools/binaries/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/var/lib/aion/home

WORKDIR /opt/aion

# These are runtime libraries for the pinned Linux tools shipped in the image.
# Python dependencies are installed exclusively from the bundled wheelhouse.
RUN apt-get update \
    && apt-get install --no-install-recommends --yes \
        bubblewrap \
        binutils \
        ca-certificates \
        file \
        libatomic1 \
        libbabeltrace1 \
        libbz2-1.0 \
        libcapstone5 \
        libc6 \
        libexpat1 \
        libipt2 \
        libgcc-s1 \
        liblzma5 \
        libmpfr6 \
        libncurses6 \
        libpcap0.8t64 \
        libpcre2-8-0 \
        libreadline8 \
        libsource-highlight4t64 \
        libssh2-1t64 \
        libstdc++6 \
        libtinfo6 \
        libxml2 \
        libzstd1 \
        procps \
        zlib1g \
    && echo 'deb http://deb.debian.org/debian bookworm main' > /etc/apt/sources.list.d/aion-bookworm.list \
    && apt-get update \
    && apt-get install --no-install-recommends --yes libpcre3 \
    && ln -s /usr/lib/x86_64-linux-gnu/libpcre.so.3 /usr/lib/x86_64-linux-gnu/libpcre.so.1 \
    && ln -s /usr/lib/x86_64-linux-gnu/libpcap.so.1.10.5 /usr/lib/x86_64-linux-gnu/libpcap.so.1 \
    && rm -f /etc/apt/sources.list.d/aion-bookworm.list \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml requirements.lock ./
COPY agent ./agent
COPY challenges_sdk ./challenges_sdk
COPY third_party ./third_party
COPY tools ./tools
COPY scripts/online_runtime.py ./scripts/online_runtime.py
COPY scripts/build_cyberchef_python.py scripts/check_enhanced_toolchain.py scripts/check_cyberchef_toolchain.py ./scripts/
COPY --from=radare2-build /opt/radare2/lib-runtime ./tools/binaries/radare2-runtime/lib
COPY --from=radare2-build /opt/radare2/share/radare2-runtime ./tools/binaries/radare2-runtime/share/radare2

ENV LD_LIBRARY_PATH=/opt/aion/tools/binaries/radare2-runtime/lib \
    R2_PREFIX=/opt/aion/tools/binaries/radare2-runtime

RUN echo /opt/aion/tools/binaries/radare2-runtime/lib > /etc/ld.so.conf.d/aion-radare2.conf \
    && ldconfig

# No package index, proxy, or network fallback is allowed here. The complete
# Linux x86_64 dependency set is already present in tools/binaries/wheelhouse.
RUN PIP_NO_INDEX=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_INDEX_URL= \
    PIP_EXTRA_INDEX_URL= \
    python tools/binaries/offline_tools.py install

RUN --network=none python scripts/build_cyberchef_python.py

# System libraries are installed on the connected image builder only.
RUN python -m playwright install-deps chromium

RUN PYTHONPATH=/opt/aion python -m compileall -q \
        agent challenges_sdk scripts \
        tools/agents tools/artifact tools/benchmark tools/binary tools/http \
        tools/network tools/pentest tools/system tools/browser tools/source tools/cyberchef tools/binaries/*.py tools/binaries/sqlmap \
    && PYTHONPATH=/opt/aion python -c \
        "import json; from tools.binaries.validation import check_tool_chain; report = check_tool_chain(); print(json.dumps(report, ensure_ascii=False, sort_keys=True)); assert report['ok'], json.dumps(report, ensure_ascii=False)"

RUN --network=none python scripts/check_enhanced_toolchain.py
RUN --network=none python scripts/check_cyberchef_toolchain.py

RUN mkdir -p -m 0700 /var/lib/aion/home /var/lib/aion/workspace /var/lib/aion/runs \
    && chmod 0755 /opt/aion/tools/binaries/bin/* \
    && test -x /usr/bin/bwrap

COPY docker/entrypoint-hosted.sh /usr/local/bin/aion-hosted-entrypoint
RUN chmod 0755 /usr/local/bin/aion-hosted-entrypoint

ENTRYPOINT ["/usr/local/bin/aion-hosted-entrypoint"]
