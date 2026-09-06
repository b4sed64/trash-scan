#!/bin/sh
# Seed a demonstration scenario against a running Trash Scan stack.
#
#   SCANNER_MODE=fake docker compose up -d --build
#   ./scripts/demo_seed.sh
#
# Creates an administrator + scanner, a lab range, two assigned targets, a
# completed passive scan, two approved active scans (SAFE then STANDARD) so the
# baseline comparison shows STILL_OBSERVED + NEW, one pending approval, and a
# generated PDF + CSV export. Idempotent-ish: run against a fresh volume.
set -e

BASE="${TRASHSCAN_BASE:-http://localhost:8080}"
ADMIN_PW="${DEMO_ADMIN_PW:-demo-admin-12345}"
SCAN_PW="${DEMO_SCANNER_PW:-demo-scanner-12345}"
JAR="$(mktemp)"
ATT="I attest this scan is authorized and will be used only for ethical, non-exploitative reconnaissance"

api() { curl -s -c "$JAR" -b "$JAR" -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' "$@"; }
id_of() { grep -oE '"id":"[^"]+"' | head -1 | cut -d'"' -f4; }

echo "==> first-run admin setup"
curl -s -c "$JAR" -X POST "$BASE/api/auth/setup" -H 'Content-Type: application/json' \
  -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PW\"}" > /dev/null
CSRF="$(grep trashscan_csrf "$JAR" | awk '{print $7}')"
[ -n "$CSRF" ] || { echo "setup failed (already initialised?)"; exit 1; }

echo "==> private scope + scanner account"
api -X POST "$BASE/api/admin/private-cidrs" -d '{"cidr":"10.10.0.0/16","note":"student lab"}' > /dev/null
SC="$(api -X POST "$BASE/api/admin/accounts" -d "{\"username\":\"scanner1\",\"password\":\"$SCAN_PW\",\"role\":\"SCANNER\"}" | id_of)"
curl -s -b "$JAR" -X PATCH "$BASE/api/admin/accounts/$SC" -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' -d '{"is_active":true}' > /dev/null

echo "==> targets + assignments"
T_DOM="$(api -X POST "$BASE/api/targets" -d '{"value":"lab.example.com","note":"demo domain"}' | id_of)"
T_IP="$(api -X POST "$BASE/api/targets" -d '{"value":"10.10.5.20","note":"demo host"}' | id_of)"
api -X POST "$BASE/api/targets/$T_DOM/assignments" -d "{\"user_id\":\"$SC\"}" > /dev/null
api -X POST "$BASE/api/targets/$T_IP/assignments"  -d "{\"user_id\":\"$SC\"}" > /dev/null

echo "==> passive discovery on the domain"
api -X POST "$BASE/api/targets/$T_DOM/scans" -d '{"profile":"PASSIVE"}' > /dev/null
api -X POST "$BASE/api/targets/$T_DOM/schedules" \
  -d '{"profile":"PASSIVE","recurrence":"INTERVAL","interval_minutes":30}' > /dev/null

wait_scan() {
  ex="$1"
  for _ in $(seq 1 30); do
    sleep 2
    st="$(api "$BASE/api/scans/$ex" | grep -oE '"state":"[^"]+"' | head -1 | cut -d'"' -f4)"
    case "$st" in COMPLETED|FAILED|TIMED_OUT|DENIED|CANCELLED) echo "    scan $ex -> $st"; return;; esac
  done
  echo "    scan $ex still $st"
}

run_active() {
  profile="$1"
  api -X POST "$BASE/api/targets/$T_IP/scans" \
    -d "{\"profile\":\"$profile\",\"attestation_text\":\"$ATT\"}" > /dev/null
  aid="$(api "$BASE/api/approvals?include_decided=false" | id_of)"
  echo "==> approving $profile active scan ($aid)"
  api -X POST "$BASE/api/approvals/$aid/approve" > /dev/null
  ex="$(api "$BASE/api/approvals/$aid" | grep -oE '"execution_id":"[^"]+"' | head -1 | cut -d'"' -f4)"
  wait_scan "$ex"
}

run_active SAFE_ACTIVE
run_active STANDARD_ACTIVE

echo "==> leaving one more active scan pending approval"
api -X POST "$BASE/api/targets/$T_IP/scans" \
  -d "{\"profile\":\"SAFE_ACTIVE\",\"attestation_text\":\"$ATT\"}" > /dev/null

echo "==> generating a PDF report and a CSV export for the host"
api -X POST "$BASE/api/targets/$T_IP/reports" -d '{"format":"PDF"}' > /dev/null
api -X POST "$BASE/api/targets/$T_IP/reports" -d '{"format":"CSV_ZIP"}' > /dev/null

echo
echo "Demo ready at $BASE"
echo "  administrator : admin / $ADMIN_PW"
echo "  scanner       : scanner1 / $SCAN_PW"
rm -f "$JAR"
