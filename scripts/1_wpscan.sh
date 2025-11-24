#!/bin/bash
set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/wpscan_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 WPScan - 빠른 스캔 ⚡"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"
echo ""

# 빠른 스캔 (플러그인만, mixed 모드)
WPSCAN_CMD="wpscan --url ${TARGET_BASE} \
    --format json \
    --output ${OUTPUT_JSON} \
    --enumerate p \
    --plugins-detection mixed \
    --random-user-agent \
    --max-threads 10 \
    --request-timeout 10 \
    --connect-timeout 10"

WPSCAN_API_TOKEN="${WPSCAN_API_TOKEN:-}"
if [ -n "$WPSCAN_API_TOKEN" ]; then
    echo "✅ API Token (빠른 모드)"
    WPSCAN_CMD="$WPSCAN_CMD --api-token ${WPSCAN_API_TOKEN}"
else
    echo "⚠️  무료 모드"
    WPSCAN_CMD="$WPSCAN_CMD --no-update"
fi

echo ""
echo "실행 중... (2-3분 예상)"
eval $WPSCAN_CMD 2>&1 || true

echo ""
echo "✅ WPScan 완료"
echo "결과: ${OUTPUT_JSON}"

if [ -f "${OUTPUT_JSON}" ]; then
    vuln_count=$(jq '[.plugins // {} | to_entries[] | .value.vulnerabilities // []] | add | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)
    echo "발견된 CVE: ${vuln_count}개"
fi