#!/bin/sh
set -eu

require_env() {
    name="$1"
    eval "value=\${$name-}"
    if [ -z "$value" ]; then
        echo "[hosted] missing required environment variable: $name" >&2
        exit 64
    fi
}

require_env BENCHMARK_TOKEN
require_env BENCHMARK_BASE_URL
require_env LLM_BASE_URL
require_env LLM_MODEL
require_env LLM_API_KEY

case "$LLM_BASE_URL" in
    http://*.tsecbench.gw|http://*.tsecbench.gw/*)
        ;;
    *)
        echo "[hosted] LLM_BASE_URL must use an allowed http://*.tsecbench.gw gateway" >&2
        exit 64
        ;;
esac

umask 077
mkdir -p /var/lib/aion/home /var/lib/aion/workspace /var/lib/aion/runs

exec python /opt/aion/scripts/online_runtime.py \
    --hosted \
    --workspace-root /var/lib/aion/workspace \
    --run-root /var/lib/aion/runs \
    "$@"
