#!/usr/bin/env bash
# Sends one CI event to mybuilds. The JSON body is read from stdin and signed
# exactly as sent; the contract is in mybuilds' docs/ingestion.md.
#
# Reporting never fails the release: a missing secret, an outage or a
# rejected body becomes a warning on the run, and the deploy carries on.
set -uo pipefail

url="${MYBUILDS_URL:-https://mybuilds.brendanmanley.com}/api/v1/ci-events"
body="$(cat)"
type="$(jq -r '.type' <<<"${body}")"

if [ -z "${MYBUILDS_CI_EVENT_SECRET:-}" ]; then
  echo "::warning::MYBUILDS_CI_EVENT_SECRET is not set; ${type} was not reported to mybuilds"
  exit 0
fi

sig="sha256=$(printf '%s' "${body}" | openssl dgst -sha256 -hmac "${MYBUILDS_CI_EVENT_SECRET}" -r | cut -d' ' -f1)"
response="$(mktemp)"
errors="$(mktemp)"

# curl retries only transient failures (timeouts, refused connections, 429
# and 5xx), and a resend of the same event is stored once, so retrying is
# safe. A 401 or 422 is final.
code="$(curl --silent --show-error \
  --max-time 10 --retry 5 --retry-connrefused --retry-delay 2 \
  -H "Content-Type: application/json" \
  -H "X-Mybuilds-Signature-256: ${sig}" \
  --data-binary "${body}" \
  --output "${response}" --write-out '%{http_code}' \
  "${url}" 2>"${errors}")"

if [[ "${code}" =~ ^2 ]]; then
  echo "Reported ${type} to mybuilds: $(cat "${response}")"
else
  echo "::warning::Could not report ${type} to mybuilds (HTTP ${code:-000}): $({ cat "${response}"; tail -n 1 "${errors}"; } | tr '\n' ' ')"
fi
rm -f "${response}" "${errors}"
