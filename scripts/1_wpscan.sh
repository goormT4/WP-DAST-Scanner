#!/bin/bash
set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/wpscan_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 WPScan - 균형 잡힌 CVE 탐지 ⚖️"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"
echo ""

# 균형 모드: 플러그인 + 테마 + 정확한 버전 탐지
WPSCAN_CMD="wpscan --url ${TARGET_BASE} \
    --format json \
    --output ${OUTPUT_JSON} \
    --enumerate p,t \
    --plugins-detection mixed \
    --plugins-version-detection aggressive \
    --random-user-agent \
    --max-threads 5 \
    --request-timeout 15 \
    --connect-timeout 10"

WPSCAN_API_TOKEN="${WPSCAN_API_TOKEN:-}"
if [ -n "$WPSCAN_API_TOKEN" ]; then
    echo "✅ API Token 사용 (균형 모드)"
    WPSCAN_CMD="$WPSCAN_CMD --api-token ${WPSCAN_API_TOKEN}"
else
    echo "⚠️  무료 모드"
    WPSCAN_CMD="$WPSCAN_CMD --no-update"
fi

echo ""
echo "실행 중... (4-6분 예상)"
echo "  - 플러그인 탐지 (mixed)"
echo "  - 버전 확인 (aggressive)"
echo "  - 테마 스캔"
echo ""

eval $WPSCAN_CMD 2>&1 || true

echo ""
echo "✅ WPScan 완료"
echo "결과: ${OUTPUT_JSON}"

if [ -f "${OUTPUT_JSON}" ]; then
    vuln_count=$(jq '[.plugins // {} | to_entries[] | .value.vulnerabilities // []] | add | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)
    plugin_count=$(jq '.plugins // {} | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)
    echo "발견된 플러그인: ${plugin_count}개"
    echo "발견된 CVE: ${vuln_count}개"
fi