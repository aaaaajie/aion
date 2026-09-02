#!/bin/sh
set -eu

CAIDO_PORT="${AION_CAIDO_PORT:-48080}"
CAIDO_PROXY_PORT="${AION_CAIDO_PROXY_PORT:-48081}"
case "$CAIDO_PORT" in
    ''|*[!0-9]*)
        echo "[hosted] AION_CAIDO_PORT must be numeric" >&2
        exit 64
        ;;
esac
if [ "$CAIDO_PORT" -lt 1 ] || [ "$CAIDO_PORT" -gt 65535 ]; then
    echo "[hosted] AION_CAIDO_PORT must be between 1 and 65535" >&2
    exit 64
fi
case "$CAIDO_PROXY_PORT" in
    ''|*[!0-9]*)
        echo "[hosted] AION_CAIDO_PROXY_PORT must be numeric" >&2
        exit 64
        ;;
esac
if [ "$CAIDO_PROXY_PORT" -lt 1 ] || [ "$CAIDO_PROXY_PORT" -gt 65535 ]; then
    echo "[hosted] AION_CAIDO_PROXY_PORT must be between 1 and 65535" >&2
    exit 64
fi
if [ "$CAIDO_PORT" -eq "$CAIDO_PROXY_PORT" ]; then
    echo "[hosted] AION_CAIDO_PORT and AION_CAIDO_PROXY_PORT must differ" >&2
    exit 64
fi

CAIDO_PID=""
AION_PID=""

cleanup() {
    set +e
    if [ -n "$CAIDO_PID" ] && kill -0 "$CAIDO_PID" 2>/dev/null; then
        kill -TERM "$CAIDO_PID" 2>/dev/null
    fi
    if [ -n "$CAIDO_PID" ]; then
        wait "$CAIDO_PID" 2>/dev/null
    fi
}

forward_stop() {
    if [ -n "$AION_PID" ] && kill -0 "$AION_PID" 2>/dev/null; then
        kill -TERM "$AION_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT
trap forward_stop INT TERM

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

LOCAL_CAIDO_URL="http://127.0.0.1:${CAIDO_PORT}"
LOCAL_CAIDO_PROXY_URL="http://127.0.0.1:${CAIDO_PROXY_PORT}"
if [ -z "${AION_CAIDO_URL:-}" ] && [ "${AION_CAIDO_ENABLED:-1}" != "0" ]; then
    export AION_CAIDO_URL="$LOCAL_CAIDO_URL"
    export AION_CAIDO_PROXY_URL="${AION_CAIDO_PROXY_URL:-$LOCAL_CAIDO_PROXY_URL}"
    export AGENT_BROWSER_CA_CERT="${AGENT_BROWSER_CA_CERT:-/usr/local/share/ca-certificates/aion-caido.crt}"
    CAIDO_LOG="/tmp/aion-caido.log"
    CAIDO_UID="$(id -u aion-caido)"
    CAIDO_GID="$(id -g aion-caido)"
    setpriv --reuid="$CAIDO_UID" --regid="$CAIDO_GID" --init-groups \
        env HOME=/var/lib/aion/caido \
            XDG_CONFIG_HOME=/var/lib/aion/caido/.config \
            caido-cli --ui-listen "127.0.0.1:${CAIDO_PORT}" \
                --proxy-listen "127.0.0.1:${CAIDO_PROXY_PORT}" \
                --allow-guests \
                --no-logging \
                --no-open \
                --import-ca-cert /var/lib/aion/caido/ca.p12 \
                --import-ca-cert-pass "" >"$CAIDO_LOG" 2>&1 &
    CAIDO_PID=$!
    echo "[hosted] Caido started on ${AION_CAIDO_URL} (pid ${CAIDO_PID})"

    CAIDO_READY=0
    i=0
    while [ "$i" -lt 30 ]; do
        if ! kill -0 "$CAIDO_PID" 2>/dev/null; then
            echo "[hosted] Caido exited during startup" >&2
            cat "$CAIDO_LOG" >&2 2>/dev/null || true
            exit 1
        fi
        status="$(curl --noproxy '*' -sS -o /dev/null -w '%{http_code}' \
            "${AION_CAIDO_URL}/graphql/" 2>/dev/null || true)"
        case "$status" in
            200|400)
                CAIDO_READY=1
                break
                ;;
        esac
        i=$((i + 1))
        sleep 1
    done
    if [ "$CAIDO_READY" -ne 1 ]; then
        echo "[hosted] Caido did not become ready within 30 seconds" >&2
        cat "$CAIDO_LOG" >&2 2>/dev/null || true
        exit 1
    fi
    echo "[hosted] Caido API is ready"
elif [ -n "${AION_CAIDO_URL:-}" ] && [ -z "${AION_CAIDO_PROXY_URL:-}" ]; then
    export AION_CAIDO_PROXY_URL="$AION_CAIDO_URL"
fi

python /opt/aion/scripts/online_runtime.py \
    --hosted \
    --workspace-root /var/lib/aion/workspace \
    --run-root /var/lib/aion/runs \
    "$@" &
AION_PID=$!
set +e
wait "$AION_PID"
status=$?
set -e
exit "$status"
