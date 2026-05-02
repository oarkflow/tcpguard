#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PORT="${TCPGUARD_E2E_PORT:-$((35080 + RANDOM % 1000))}"
BASE_URL="http://127.0.0.1:${PORT}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/tcpguard-production-ready.XXXXXX")"
LOG_FILE="${WORK_DIR}/server.log"
DB_PATH="${WORK_DIR}/tcpguard.db"
AUTH_SECRET="${TCPGUARD_AUTH_SECRET:-tcpguard-production-ready-secret-32b}"
CSRF_TOKEN="${TCPGUARD_CSRF_TOKEN:-tcpguard-production-ready-csrf}"
SERVER_PID=""
FAILURES=0

cleanup() {
  if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
  rm -rf "${WORK_DIR}"
}
trap cleanup EXIT INT TERM

status_code() {
  curl -sS -o "${WORK_DIR}/body.txt" -w "%{http_code}" "$@"
}

check_status() {
  local label="$1"
  local want="$2"
  shift 2

  local got
  got="$(status_code "$@")"
  if [[ "${got}" == "${want}" ]]; then
    printf 'PASS %-44s %s\n' "${label}" "${got}"
  else
    printf 'FAIL %-44s got %s want %s\n' "${label}" "${got}" "${want}"
    sed 's/^/  body: /' "${WORK_DIR}/body.txt"
    FAILURES=$((FAILURES + 1))
  fi
}

wait_for_server() {
  for _ in $(seq 1 160); do
    if [[ -n "${SERVER_PID}" ]] && ! kill -0 "${SERVER_PID}" 2>/dev/null; then
      return 1
    fi
    if curl -fsS "${BASE_URL}/ready" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

cd "${ROOT_DIR}" || exit 1

printf 'Starting production-ready example on %s\n' "${BASE_URL}"
GOCACHE="${WORK_DIR}/gocache" \
  TCPGUARD_AUTH_SECRET="${AUTH_SECRET}" \
  TCPGUARD_CSRF_TOKEN="${CSRF_TOKEN}" \
  TCPGUARD_ADDR=":${PORT}" \
  TCPGUARD_DB="${DB_PATH}" \
  TCPGUARD_TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128" \
  go run ./examples/production-ready >"${LOG_FILE}" 2>&1 &
SERVER_PID="$!"

if ! wait_for_server; then
  printf 'FAIL server did not become ready\n'
  sed 's/^/  server: /' "${LOG_FILE}" || true
  exit 1
fi

VIEWER_TOKEN="$(GOCACHE="${WORK_DIR}/gocache" TCPGUARD_AUTH_SECRET="${AUTH_SECRET}" go run ./examples/production-ready token viewer config_viewer)"
EDITOR_TOKEN="$(GOCACHE="${WORK_DIR}/gocache" TCPGUARD_AUTH_SECRET="${AUTH_SECRET}" go run ./examples/production-ready token editor config_editor)"
ADMIN_TOKEN="$(GOCACHE="${WORK_DIR}/gocache" TCPGUARD_AUTH_SECRET="${AUTH_SECRET}" go run ./examples/production-ready token admin config_admin)"
RULE='{"name":"scriptProductionRule","type":"ddos","enabled":true,"actions":[{"type":"temporary_ban","duration":"10m","response":{"status":403,"message":"blocked"}}]}'
ROLE='{"id":"script_role","tenant_id":"default","name":"Script Role","permissions":[{"action":"get","resource":"config.rule:*"}]}'

check_status "readiness is healthy" 200 "${BASE_URL}/ready"
check_status "anonymous config access denied" 401 "${BASE_URL}/api/rules"
check_status "viewer can list rules" 200 \
  -H "Authorization: Bearer ${VIEWER_TOKEN}" \
  "${BASE_URL}/api/rules"
check_status "viewer cannot mutate" 403 \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${VIEWER_TOKEN}" \
  --data "${RULE}" \
  "${BASE_URL}/api/rules"
check_status "browser mutation requires csrf" 403 \
  -X POST -H "Content-Type: application/json" \
  -H "Origin: https://admin.example.com" \
  -H "Authorization: Bearer ${EDITOR_TOKEN}" \
  --data "${RULE}" \
  "${BASE_URL}/api/rules"

CREATE_HEADERS="${WORK_DIR}/create.headers"
CREATE_BODY="${WORK_DIR}/create.body"
CREATE_STATUS="$(curl -sS -D "${CREATE_HEADERS}" -o "${CREATE_BODY}" -w "%{http_code}" \
  -X POST -H "Content-Type: application/json" \
  -H "Origin: https://admin.example.com" \
  -H "X-CSRF-Token: ${CSRF_TOKEN}" \
  -H "Authorization: Bearer ${EDITOR_TOKEN}" \
  --data "${RULE}" \
  "${BASE_URL}/api/rules")"
if [[ "${CREATE_STATUS}" == "201" ]] && grep -qi '^X-Config-Version:' "${CREATE_HEADERS}"; then
  printf 'PASS %-44s %s\n' "editor creates rule with version" "${CREATE_STATUS}"
else
  printf 'FAIL %-44s got %s\n' "editor creates rule with version" "${CREATE_STATUS}"
  sed 's/^/  header: /' "${CREATE_HEADERS}"
  sed 's/^/  body: /' "${CREATE_BODY}"
  FAILURES=$((FAILURES + 1))
fi

check_status "editor cannot manage authz" 403 \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${EDITOR_TOKEN}" \
  --data "${ROLE}" \
  "${BASE_URL}/api/authz/roles"
check_status "admin can manage authz" 201 \
  -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  --data "${ROLE}" \
  "${BASE_URL}/api/authz/roles"
check_status "audit endpoint returns events" 200 \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  "${BASE_URL}/api/audit"
check_status "protected app route works" 200 "${BASE_URL}/app/ping"

if [[ "${FAILURES}" -ne 0 ]]; then
  printf '\n%d check(s) failed. Server log:\n' "${FAILURES}"
  sed 's/^/  server: /' "${LOG_FILE}" || true
  exit 1
fi

printf '\nAll production-ready e2e checks passed.\n'
