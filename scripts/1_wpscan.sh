#!/bin/bash
# 1_wpscan.sh - WPScan으로 기존 CVE 탐지

set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
WP_USERNAME="${WP_USERNAME:-}"
WP_PASSWORD="${WP_PASSWORD:-}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/wpscan_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 WPScan - 기존 CVE 탐지"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"

if [ -n "$WP_USERNAME" ] && [ -n "$WP_PASSWORD" ]; then
    echo "🔑 인증: ${WP_USERNAME}"
else
    echo "⚠️  비인증 스캔"
fi
echo ""

# WPScan 명령어 구성
WPSCAN_CMD="wpscan --url ${TARGET_BASE} \
    --format json \
    --output ${OUTPUT_JSON} \
    --plugins-detection aggressive \
    --plugins-version-detection aggressive"

# API Token 추가
WPSCAN_API_TOKEN="${WPSCAN_API_TOKEN:-}"
if [ -n "$WPSCAN_API_TOKEN" ]; then
    echo "✅ API Token 사용"
    WPSCAN_CMD="$WPSCAN_CMD --api-token ${WPSCAN_API_TOKEN}"
else
    echo "⚠️  무료 모드"
    WPSCAN_CMD="$WPSCAN_CMD --no-update"
fi

# 로그인 정보 추가
if [ -n "$WP_USERNAME" ] && [ -n "$WP_PASSWORD" ]; then
    echo "✅ 인증된 스캔 활성화"
    WPSCAN_CMD="$WPSCAN_CMD --username ${WP_USERNAME} --password ${WP_PASSWORD}"
fi

# 실행
echo ""
echo "실행 중..."
eval $WPSCAN_CMD 2>&1 || true

echo ""
echo "✅ WPScan 완료"
echo "결과: ${OUTPUT_JSON}"

if [ -f "${OUTPUT_JSON}" ]; then
    vuln_count=$(jq '[.plugins // {} | to_entries[] | .value.vulnerabilities // []] | add | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)
    echo "발견된 CVE: ${vuln_count}개"
fi