#!/bin/bash
# 5_sqlmap.sh - SQLMap SQLi 확인

set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
WP_USERNAME="${WP_USERNAME:-}"
WP_PASSWORD="${WP_PASSWORD:-}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/sqlmap_results.json"
WFUZZ_RESULTS="${RESULTS_DIR}/wfuzz_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔬 SQLMap - SQLi 확인"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"
echo ""

# 로그인해서 쿠키 얻기
COOKIE_HEADER=""
if [ -n "$WP_USERNAME" ] && [ -n "$WP_PASSWORD" ]; then
    echo "🔑 WordPress 로그인 중..."
    
    curl -s -c /tmp/wp_cookies.txt \
        -d "log=${WP_USERNAME}&pwd=${WP_PASSWORD}&wp-submit=Log+In" \
        "${TARGET_BASE}/wp-login.php" > /dev/null 2>&1 || true
    
    if [ -f /tmp/wp_cookies.txt ]; then
        COOKIE_VALUE=$(grep "wordpress_logged_in" /tmp/wp_cookies.txt | awk '{print $7}' 2>/dev/null || true)
        
        if [ -n "$COOKIE_VALUE" ]; then
            COOKIE_NAME=$(grep "wordpress_logged_in" /tmp/wp_cookies.txt | awk '{print $6}' 2>/dev/null || true)
            COOKIE_HEADER="${COOKIE_NAME}=${COOKIE_VALUE}"
            echo "✅ 로그인 성공!"
        else
            echo "⚠️  로그인 실패"
        fi
        rm -f /tmp/wp_cookies.txt
    fi
else
    echo "⚠️  비인증 스캔"
fi

echo ""

# wfuzz 결과 확인
if [ ! -f "${WFUZZ_RESULTS}" ]; then
    echo "⚠️  wfuzz 결과 없음. SQLMap 스킵."
    echo '{
  "scan_type": "sqli_confirmed",
  "tool": "sqlmap",
  "target": "'${TARGET_BASE}'",
  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
  "results": []
}' > "${OUTPUT_JSON}"
    exit 0
fi

# JSON 시작
echo '{
  "scan_type": "sqli_confirmed",
  "tool": "sqlmap",
  "target": "'${TARGET_BASE}'",
  "timestamp": "'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'",
  "results": [' > "${OUTPUT_JSON}"

first=true
confirmed_count=0

# wfuzz에서 발견된 취약점만 테스트
jq -c '.results[]?' "${WFUZZ_RESULTS}" 2>/dev/null | while read -r vuln; do
    url=$(echo "$vuln" | jq -r '.url')
    param=$(echo "$vuln" | jq -r '.parameter')
    full_url="${url}1"
    
    echo "Testing: ${param}"
    echo "  URL: ${full_url}"
    
    # SQLMap 명령어 구성
    SQLMAP_CMD="sqlmap -u ${full_url} \
        -p ${param} \
        --batch \
        --level=1 \
        --risk=1 \
        --technique=T \
        --time-sec=5 \
        --timeout=10 \
        --retries=1 \
        --flush-session"
    
    # 쿠키 추가
    if [ -n "$COOKIE_HEADER" ]; then
        echo "  🔑 인증된 요청"
        SQLMAP_CMD="$SQLMAP_CMD --cookie=\"${COOKIE_HEADER}\""
    fi
    
    # 실행
    sqlmap_output=$(eval $SQLMAP_CMD 2>&1 || true)
    
    if echo "$sqlmap_output" | grep -iq "parameter '${param}' is vulnerable"; then
        confirmed_count=$((confirmed_count + 1))
        
        if [ "$first" = false ]; then
            echo "," >> "${OUTPUT_JSON}"
        fi
        first=false
        
        echo "  🚨 확인됨!"
        
        dbms=$(echo "$sqlmap_output" | grep -oP "back-end DBMS: \K[^']*" | head -1 || echo "unknown")
        
        cat >> "${OUTPUT_JSON}" << JSONEOF
    {
      "url": "${full_url}",
      "parameter": "${param}",
      "dbms": "${dbms}",
      "authenticated": $([ -n "$COOKIE_HEADER" ] && echo "true" || echo "false"),
      "vulnerability": "sqli-confirmed",
      "severity": "CRITICAL",
      "zero_day_candidate": true
    }
JSONEOF
    else
        echo "  ℹ️  확인 실패"
    fi
    echo ""
done

# JSON 종료
echo '
  ]
}' >> "${OUTPUT_JSON}"

echo "✅ SQLMap 완료"
echo "결과: ${OUTPUT_JSON}"

confirmed=$(jq '.results | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)
echo "확인된 SQLi: ${confirmed}개"