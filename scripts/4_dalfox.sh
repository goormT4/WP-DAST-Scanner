#!/bin/bash
# 4_dalfox.sh - Dalfox XSS 탐지

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
    dalfox_output=$(dalfox url "${url}" \
        --silence \
        --format json \
        2>/dev/null || echo '[]')
    
    # 유효한 JSON인지 확인
    if echo "$dalfox_output" | jq empty 2>/dev/null; then
        # 결과가 있는지 확인
        result_count=$(echo "$dalfox_output" | jq '. | length' 2>/dev/null || echo 0)
        
        if [ "$result_count" -gt 0 ]; then
            echo "  🚨 XSS 발견: ${result_count}개"
            
            # 각 결과 처리
            echo "$dalfox_output" | jq -c '.[]' 2>/dev/null | while read -r vuln; do
                if [ "$first" = false ]; then
                    echo "," >> "${OUTPUT_JSON}"
                fi
                first=false
                total_xss=$((total_xss + 1))
                
                param=$(echo "$vuln" | jq -r '.param // "unknown"' 2>/dev/null)
                payload=$(echo "$vuln" | jq -r '.payload // ""' 2>/dev/null)
                
                cat >> "${OUTPUT_JSON}" << JSONEOF2
    {
      "url": "${url}",
      "parameter": "${param}",
      "payload": $(echo "$payload" | jq -R . 2>/dev/null || echo '""'),
      "vulnerability": "reflected-xss",
      "severity": "MEDIUM",
      "potential_zero_day": false
    }
JSONEOF2
            done
        else
            echo "  ✅ 안전"
        fi
    else
        echo "  ⚠️  Dalfox 결과 파싱 실패"
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