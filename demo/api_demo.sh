#!/bin/sh
# Week-1 API demo: register, log in, create a project, upload two
# versions, and fetch the verification page. Requires curl and jq.
# Usage: sh demo/api_demo.sh [port]
set -e
PORT="${1:-8000}"
BASE="http://127.0.0.1:$PORT"
DATA="$(mktemp -d)/prooftrail-data.json"

python3 -m prooftrail.server --port "$PORT" --data "$DATA" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 1

curl -s -X POST "$BASE/api/users" \
  -H 'Content-Type: application/json' \
  -d '{"username":"designer","name":"Freelance Designer","password":"demo-pw"}'
echo
TOKEN=$(curl -s -X POST "$BASE/api/sessions" \
  -H 'Content-Type: application/json' \
  -d '{"username":"designer","password":"demo-pw"}' | jq -r .token)
echo "token: ${TOKEN:0:12}..."

PROJECT=$(curl -s -X POST "$BASE/api/projects" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"title":"Brand Deck"}' | jq -r .project_id)
echo "project: $PROJECT"

upload() {
  printf '%s' "$1" | base64 -w0 | {
    read B64
    curl -s -X POST "$BASE/api/projects/$PROJECT/uploads" \
      -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      -d "{\"content_base64\":\"$B64\",\"label\":\"$2\"}"
    echo
  }
}
upload "Northwind Studio crafts bold brand identities." "v1"
upload "Northwind Studio crafts bold brand identities. We offer logo design." "v2"

curl -s "$BASE/api/projects/$PROJECT/versions" \
  -H "Authorization: Bearer $TOKEN" | jq .
curl -s "$BASE/api/projects/$PROJECT/verify" \
  -H "Authorization: Bearer $TOKEN" | jq '{ledger_valid, events}'
