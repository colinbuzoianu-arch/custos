#!/usr/bin/env bash
# Seeds the full-stack demo (docker-compose.yml + .control.yml + .full.yml):
# creates a Control admin, a tenant, an agent + token, a published policy,
# and enrolls the gateway with Control — then starts it.
#
# Prerequisites: docker compose, curl, jq.
#
# Usage (from the repo root, after `cp .env.example .env` if you haven't):
#   docker compose -f docker-compose.yml -f docker-compose.control.yml -f docker-compose.full.yml \
#     up -d everything postgres control
#   ./scripts/seed-demo.sh
#
# This has been read through carefully but not run against a live Docker
# daemon in the environment it was written in — if a step fails, the
# printed curl/jq output should say why; please report back what broke.
set -euo pipefail

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.control.yml -f docker-compose.full.yml)
CONTROL_URL="http://127.0.0.1:8788"
TENANT="demo"
ADMIN_EMAIL="admin@demo.test"
ADMIN_PASSWORD="correct-horse-battery-staple"
AGENT_NAME="invoice-processor"
GATEWAY_NAME="demo-gateway"
COOKIE_JAR="$(mktemp)"
trap 'rm -f "$COOKIE_JAR"' EXIT

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "FAILED: $1 is required but not found on PATH" >&2
    exit 1
  }
}
require jq
require curl

echo "==> Waiting for Control to answer /healthz..."
for _ in $(seq 1 30); do
  if curl -fs "$CONTROL_URL/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl -fs "$CONTROL_URL/healthz" >/dev/null || {
  echo "FAILED: Control never became reachable at $CONTROL_URL" >&2
  exit 1
}

echo "==> Creating the admin user (tenant: $TENANT)..."
"${COMPOSE[@]}" exec -T -e CUSTOS_CONTROL_ADMIN_PASSWORD="$ADMIN_PASSWORD" control \
  custos-control create-admin \
  --config /etc/custos-control/custos-control.toml \
  --email "$ADMIN_EMAIL" --tenant "$TENANT" \
  || echo "  (already exists — continuing)"

echo "==> Logging in..."
LOGIN_RESPONSE=$(curl -fs -c "$COOKIE_JAR" -X POST "$CONTROL_URL/api/login" \
  -H "content-type: application/json" \
  -d "{\"tenant\":\"$TENANT\",\"email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}")
CSRF_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.csrf_token')
[ -n "$CSRF_TOKEN" ] && [ "$CSRF_TOKEN" != "null" ] || {
  echo "FAILED: login did not return a csrf_token: $LOGIN_RESPONSE" >&2
  exit 1
}

api() {
  # api METHOD PATH [JSON_BODY]
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -fs -b "$COOKIE_JAR" -X "$method" "$CONTROL_URL/api$path" \
      -H "content-type: application/json" -H "x-csrf-token: $CSRF_TOKEN" -d "$body"
  else
    curl -fs -b "$COOKIE_JAR" -X "$method" "$CONTROL_URL/api$path" \
      -H "x-csrf-token: $CSRF_TOKEN"
  fi
}

echo "==> Creating agent '$AGENT_NAME'..."
AGENT=$(api POST /agents "{\"name\":\"$AGENT_NAME\",\"description\":\"Demo agent, seeded by scripts/seed-demo.sh\"}")
AGENT_ID=$(echo "$AGENT" | jq -r '.id')
[ -n "$AGENT_ID" ] && [ "$AGENT_ID" != "null" ] || {
  echo "FAILED: could not create agent: $AGENT" >&2
  exit 1
}

echo "==> Issuing its token (shown once — save it)..."
TOKEN_RESPONSE=$(api POST "/agents/$AGENT_ID/token")
AGENT_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.token')

echo "==> Saving and publishing a policy..."
POLICY_TEXT='@id("invoice-processor-read")
permit (
    principal == Agent::"'"$AGENT_NAME"'",
    action == Action::"call_tool",
    resource
) when {
    [Tool::"echo", Tool::"get-sum"].contains(resource)
};'
# jq builds the JSON body so the policy text's own quotes/newlines are
# escaped correctly, rather than hand-escaping them into the curl command.
DRAFT_BODY=$(jq -n --arg text "$POLICY_TEXT" '{policy_text: $text, message: "seeded by scripts/seed-demo.sh"}')
DRAFT=$(api POST /policies "$DRAFT_BODY")
VERSION=$(echo "$DRAFT" | jq -r '.version')
VALID=$(echo "$DRAFT" | jq -r '.valid')
[ "$VALID" = "true" ] || {
  echo "FAILED: seeded policy did not validate: $DRAFT" >&2
  exit 1
}
api POST "/policies/$VERSION/publish" >/dev/null
echo "  published v$VERSION"

echo "==> Creating a one-time gateway enrollment token..."
ENROLL_RESPONSE=$(api POST /gateways/enroll-tokens)
ENROLL_TOKEN=$(echo "$ENROLL_RESPONSE" | jq -r '.token')

echo "==> Enrolling the gateway with Control..."
"${COMPOSE[@]}" run --rm --no-deps custos \
  enroll --control http://control:8788 --token "$ENROLL_TOKEN" \
  --name "$GATEWAY_NAME" --state-path /var/lib/custos/control-state.json

echo "==> Starting the gateway..."
"${COMPOSE[@]}" up -d custos

cat <<EOF

==> Done.

Agent token (shown once, save it now): $AGENT_TOKEN

The gateway polls Control every 5s (config/custos.full.toml) and needs one
successful sync before it recognizes this token — give it ~10s, or watch:
  docker compose -f docker-compose.yml -f docker-compose.control.yml -f docker-compose.full.yml logs -f custos

Then drive it as the agent exactly as in the "cargo run" section of
docs/DEMO.md, using this token and base URL http://127.0.0.1:8787/mcp.

The dashboard (once built and embedded — see docs/decisions/0006-dashboard.md's
open item) isn't served by the control image yet; run it separately with
'cd dashboard && npm install && npm run dev' against this same Control
instance in the meantime.
EOF
