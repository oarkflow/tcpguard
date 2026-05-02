#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${TCPGUARD_E2E_PORT:-33080}"
BASE_URL="http://127.0.0.1:${PORT}"
CONFIG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tcpguard-config-api-authz.XXXXXX")"
LOG_FILE="${CONFIG_DIR}/server.log"
SERVER_PID=""
FAILURES=0

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${CONFIG_DIR}"
}
trap cleanup EXIT INT TERM

status_code() {
  curl -sS -o /tmp/tcpguard-e2e-body.txt -w "%{http_code}" "$@"
}

check_status() {
  local label="$1"
  local want="$2"
  shift 2

  local got
  got="$(status_code "$@")"
  if [[ "${got}" == "${want}" ]]; then
    printf 'PASS %-42s %s\n' "${label}" "${got}"
  else
    printf 'FAIL %-42s got %s want %s\n' "${label}" "${got}" "${want}"
    sed 's/^/  body: /' /tmp/tcpguard-e2e-body.txt
    FAILURES=$((FAILURES + 1))
  fi
}

wait_for_server() {
  for _ in $(seq 1 60); do
    if curl -fsS "${BASE_URL}/" >/dev/null 2>&1; then
      return 0
    fi
    if [[ -n "${SERVER_PID}" ]] && ! kill -0 "${SERVER_PID}" 2>/dev/null; then
      return 1
    fi
    sleep 0.25
  done
  return 1
}

cd "${ROOT_DIR}" || exit 1

printf 'Starting config-api-authz example on %s\n' "${BASE_URL}"
GOCACHE="${CONFIG_DIR}/gocache" TCPGUARD_ADDR=":${PORT}" TCPGUARD_CONFIG_DIR="${CONFIG_DIR}" go run ./examples/config-api-authz >"${LOG_FILE}" 2>&1 &
SERVER_PID="$!"

if ! wait_for_server; then
  printf 'FAIL server did not become ready\n'
  sed 's/^/  server: /' "${LOG_FILE}" || true
  exit 1
fi

RULE='{"name":"scriptRule","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}'
BLOCKED_RULE='{"name":"blockedRule","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}'
ROLE='{"id":"script_role","tenant_id":"default","name":"Script Role","permissions":[{"action":"get","resource":"config.rule:*"}]}'

check_status "anonymous denied" 403 \
  "${BASE_URL}/api/rules"

check_status "viewer can list rules" 200 \
  -H "X-Demo-User: viewer" -H "X-Demo-Roles: config_viewer" \
  "${BASE_URL}/api/rules"

check_status "viewer cannot create rule" 403 \
  -X POST -H "Content-Type: application/json" \
  -H "X-Demo-User: viewer" -H "X-Demo-Roles: config_viewer" \
  --data "${RULE}" \
  "${BASE_URL}/api/rules"

CREATE_HEADERS="${CONFIG_DIR}/create.headers"
CREATE_BODY="${CONFIG_DIR}/create.body"
CREATE_STATUS="$(curl -sS -D "${CREATE_HEADERS}" -o "${CREATE_BODY}" -w "%{http_code}" \
  -X POST -H "Content-Type: application/json" \
  -H "X-Demo-User: editor" -H "X-Demo-Roles: config_editor" \
  --data "${RULE}" \
  "${BASE_URL}/api/rules")"
if [[ "${CREATE_STATUS}" == "201" ]] && grep -qi '^X-Config-Version:' "${CREATE_HEADERS}"; then
  printf 'PASS %-42s %s\n' "editor creates rule with version" "${CREATE_STATUS}"
else
  printf 'FAIL %-42s got %s and headers:\n' "editor creates rule with version" "${CREATE_STATUS}"
  sed 's/^/  header: /' "${CREATE_HEADERS}"
  sed 's/^/  body: /' "${CREATE_BODY}"
  FAILURES=$((FAILURES + 1))
fi

check_status "ACL deny blocks editor update" 403 \
  -X PUT -H "Content-Type: application/json" \
  -H "X-Demo-User: editor" -H "X-Demo-Roles: config_editor" \
  --data "${BLOCKED_RULE}" \
  "${BASE_URL}/api/rules/blockedRule"

check_status "stale If-Match returns conflict" 409 \
  -X PUT -H "Content-Type: application/json" -H "If-Match: 1" \
  -H "X-Demo-User: editor" -H "X-Demo-Roles: config_editor" \
  --data "${RULE}" \
  "${BASE_URL}/api/rules/scriptRule"

check_status "editor cannot manage authz" 403 \
  -X POST -H "Content-Type: application/json" \
  -H "X-Demo-User: editor" -H "X-Demo-Roles: config_editor" \
  --data "${ROLE}" \
  "${BASE_URL}/api/authz/roles"

check_status "admin can manage authz" 201 \
  -X POST -H "Content-Type: application/json" \
  -H "X-Demo-User: admin" -H "X-Demo-Roles: config_admin" \
  --data "${ROLE}" \
  "${BASE_URL}/api/authz/roles"

check_status "audit endpoint returns events" 200 \
  "${BASE_URL}/demo/audit"

if [[ "${FAILURES}" -ne 0 ]]; then
  printf '\n%d check(s) failed. Server log:\n' "${FAILURES}"
  sed 's/^/  server: /' "${LOG_FILE}" || true
  exit 1
fi

printf '\nAll config-api-authz e2e checks passed.\n'
