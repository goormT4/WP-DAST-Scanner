#!/bin/bash
# 4_scan_dalfox.sh - Dalfox XSS 탐지

set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/dalfox_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 Dalfox - XSS 탐지"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"
echo ""

# 테스트 URL들
declare -a TEST_URLS=(
    "${TARGET_BASE}/?s=FUZZ"
    "${TARGET_BASE}/wp-admin/admin.php?page=wps_pages_page&id=FUZZ"
    "${TARGET_BASE}/wp-comments-post.php?comment=FUZZ"
)

# JSON 시작
echo '{
  "scan_type": "xss",
  "tool": "dalfox",
  "target": "'${TARGET_BASE}'",
  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
  "results": [' > "${OUTPUT_JSON}"

first=true
total_xss=0

for url in "${TEST_URLS[@]}"; do
    echo "Testing XSS: ${url}"
    
    # Dalfox 실행
    dalfox url "${url}" \
        --silence \
        --format json \
        --output /tmp/dalfox_temp.json 2>/dev/null || true
    
    if [ -f /tmp/dalfox_temp.json ] && [ -s /tmp/dalfox_temp.json ]; then
        # 결과 파싱
        jq -c '.[]?' /tmp/dalfox_temp.json 2>/dev/null | while read -r vuln; do
            if [ "$first" = false ]; then
                echo "," >> "${OUTPUT_JSON}"
            fi
            first=false
            total_xss=$((total_xss + 1))
            
            param=$(echo "$vuln" | jq -r '.param // "unknown"')
            payload=$(echo "$vuln" | jq -r '.payload // ""')
            
            echo "  🚨 XSS 발견: ${param}"
            
            cat >> "${OUTPUT_JSON}" << EOF
    {
      "url": "${url}",
      "parameter": "${param}",
      "payload": $(echo "$payload" | jq -R .),
      "vulnerability": "reflected-xss",
      "severity": "MEDIUM",
      "potential_zero_day": false
    }
EOF
        done
        rm -f /tmp/dalfox_temp.json
    fi
done

# JSON 종료
echo '
  ]
}' >> "${OUTPUT_JSON}"

echo ""
echo "✅ Dalfox 스캔 완료"
echo "결과: ${OUTPUT_JSON}"

xss_count=$(jq '.results | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)
echo "발견된 XSS: ${xss_count}개"