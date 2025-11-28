#!/bin/bash
set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/nuclei_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 Nuclei - WordPress 템플릿 스캔"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"
echo ""

# Nuclei 템플릿 업데이트
echo "📦 Nuclei 템플릿 업데이트 중..."
nuclei -update-templates 2>&1 | tail -1

echo ""
echo "🔍 WordPress 관련 템플릿 스캔 중..."

# ✅ 태그 기반 스캔 (경로 문제 없음!)
nuclei -u "${TARGET_BASE}" \
    -tags wordpress,wp,wp-plugin,wp-theme,cve \
    -severity critical,high,medium \
    -jsonl \
    -o "${OUTPUT_JSON}" \
    -silent \
    2>&1 || true

echo ""
echo "✅ Nuclei 스캔 완료"
echo "결과: ${OUTPUT_JSON}"

# 발견된 취약점 개수
if [ -f "${OUTPUT_JSON}" ]; then
    vuln_count=$(wc -l < "${OUTPUT_JSON}" 2>/dev/null || echo 0)
    echo "발견된 취약점: ${vuln_count}개"
    
    if [ "$vuln_count" -gt 0 ]; then
        echo ""
        echo "템플릿 ID:"
        jq -r '.["template-id"]' "${OUTPUT_JSON}" 2>/dev/null | sort -u || true
    fi
else
    echo "⚠️ 결과 파일 없음"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"