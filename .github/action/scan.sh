#!/usr/bin/env bash
#
# The body of the Merlon GitHub Action.
#
# Deliberately thin. Everything that involves a decision — the severity
# ordering, what "proven" means, whether a finding breaches the threshold —
# lives in `app.cli`, where it is covered by the Python test-suite. Logic that
# only exists inside a workflow file is logic nobody can test, and a build gate
# that silently stops gating is worse than no gate at all.
set -euo pipefail

REPORT_DIR="${RUNNER_TEMP:-/tmp}/merlon"
REPORT="${REPORT_DIR}/report.json"
mkdir -p "${REPORT_DIR}"

echo "Pulling ${MERLON_IMAGE}…"
docker pull --quiet "${MERLON_IMAGE}"

echo "Scanning ${TARGET} (depth: ${DEPTH}, fail-on: ${FAIL_ON})…"
status=0
docker run --rm \
  -e MERLON_DB_PATH=/out/merlon.db \
  -e MERLON_ARTIFACT_DIR=/out/artifacts \
  -e MERLON_AUTO_UPDATE=0 \
  -v "${REPORT_DIR}":/out \
  "${MERLON_IMAGE}" \
  python -m app.cli scan \
    --target "${TARGET}" \
    --depth "${DEPTH}" \
    --authorized \
    --authorized-by "${AUTHORIZED_BY}" \
    --fail-on "${FAIL_ON}" \
    $( [ "${ONLY_PROVEN}" = "true" ] && echo --only-proven ) \
    --json /out/report.json || status=$?

if [ ! -s "${REPORT}" ]; then
  echo "::error::the scan produced no report"
  exit 1
fi

total=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["findings"]))' "${REPORT}")
{
  echo "findings=${total}"
  echo "report=${REPORT}"
} >> "${GITHUB_OUTPUT:-/dev/null}"

if [ "${status}" -ne 0 ]; then
  echo "::error::Merlon found findings at or above '${FAIL_ON}'. See ${REPORT}."
  exit "${status}"
fi

echo "${total} finding(s); none at or above '${FAIL_ON}'."
