#!/bin/bash
set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/sqlmap_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔬 SQLMap - 독립 SQLi 확인 💪"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"
echo ""
echo "🎯 wfuzz 결과와 무관하게 독립 실행"
echo ""

# 주요 공개 엔드포인트만 테스트
TEST_URLS=(
    "${TARGET_BASE}/?s=1"
    "${TARGET_BASE}/?p=1"
    "${TARGET_BASE}/?cat=1"
    "${TARGET_BASE}/?author=1"
)

# JSON 시작
cat > "${OUTPUT_JSON}" << JSONSTART
{
  "scan_type": "sqli",
  "tool": "sqlmap",
  "target": "${TARGET_BASE}",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "results": [
JSONSTART

first=true
confirmed=0

for test_url in "${TEST_URLS[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Testing SQLi: ${test_url}"
    echo ""
    
    SQLMAP_OUTPUT="/tmp/sqlmap_$$_$(date +%s).txt"
    
    # SQLMap 빠른 모드
    sqlmap -u "${test_url}" \
        --batch \
        --level=2 \
        --risk=2 \
        --threads=3 \
        --timeout=10 \
        --retries=1 \
        --technique=BEUST \
        --tamper=space2comment \
        --random-agent \
        2>&1 | tee "$SQLMAP_OUTPUT" || true
    
    # 결과 확인
    if grep -q "Parameter:.*is vulnerable" "$SQLMAP_OUTPUT" 2>/dev/null; then
        confirmed=$((confirmed + 1))
        
        [ "$first" = false ] && echo "," >> "${OUTPUT_JSON}"
        first=false
        
        echo "🚨 SQLi 확인됨!"
        
        # 취약한 파라미터 추출
        vuln_param=$(grep "Parameter:" "$SQLMAP_OUTPUT" | head -1 | awk '{print $2}' | tr -d "'" || echo "unknown")
        vuln_type=$(grep "Type:" "$SQLMAP_OUTPUT" | head -1 | cut -d':' -f2- | xargs || echo "unknown")
        
        cat >> "${OUTPUT_JSON}" << VULNEOF
    {
      "url": "${test_url}",
      "parameter": "${vuln_param}",
      "vulnerability": "sql-injection",
      "technique": "${vuln_type}",
      "severity": "CRITICAL",
      "confirmed": true,
      "potential_zero_day": true
    }
VULNEOF
        echo "✅ SQLi 확인!"
    else
        echo "✅ 안전 (SQLMap 확인 안 됨)"
    fi
    
    rm -f "$SQLMAP_OUTPUT"
    echo ""
done

# JSON 종료
cat >> "${OUTPUT_JSON}" << JSONEND
  ]
}
JSONEND

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ SQLMap 완료"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "확인된 SQLi: ${confirmed}개"