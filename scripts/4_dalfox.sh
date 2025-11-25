#!/bin/bash
set -e

TARGET_BASE="${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}"
RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/dalfox_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 Dalfox - 실전 XSS 탐지 💪"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Target: ${TARGET_BASE}"
echo ""

# 실전 URL: 공개 페이지만!
TEST_URLS=(
    "${TARGET_BASE}/?s=FUZZ"
    "${TARGET_BASE}/?p=FUZZ"
    "${TARGET_BASE}/?cat=FUZZ"
    "${TARGET_BASE}/?author=FUZZ"
    "${TARGET_BASE}/wp-comments-post.php?comment=FUZZ"
)

# 임시 파일 (JSONL 형태)
TEMP_OUTPUT="/tmp/dalfox_all_$$.jsonl"
> "$TEMP_OUTPUT"

total_xss=0

for url in "${TEST_URLS[@]}"; do
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "Testing XSS: ${url}"
    echo ""
    
    TEMP_RESULT="/tmp/dalfox_single_$$.json"
    
    # ✅ 개선 1: 공격적인 모드로 변경!
    dalfox url "${url}" \
        --format json \
        --output "$TEMP_RESULT" \
        --mining-dict \
        --mining-dom \
        --mining-dict-word /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
        --worker 20 \
        --delay 0 \
        --timeout 30 \
        --follow-redirects \
        --custom-payload '<img src=x onerror=alert(1)>' \
        --custom-payload '"><svg onload=alert(1)>' \
        --custom-payload "'-alert(1)-'" \
        --custom-payload 'javascript:alert(1)' \
        2>/dev/null || true
    
    if [ -f "$TEMP_RESULT" ] && [ -s "$TEMP_RESULT" ]; then
        echo "📄 Dalfox 원본 결과:"
        cat "$TEMP_RESULT"
        echo ""
        
        if jq empty "$TEMP_RESULT" 2>/dev/null; then
            # ✅ 개선 2: 빈 객체 엄격히 필터링
            result_count=$(jq '
              [if type=="array" then .[] else . end] |
              map(select(
                . != null and 
                . != {} and 
                (. | length) > 0 and
                (.param // .parameter // "") != "" and
                (.param // .parameter // "") != "unknown"
              )) |
              length
            ' "$TEMP_RESULT" 2>/dev/null || echo 0)
            
            echo "📊 유효한 결과: ${result_count}개"
            
            if [ "$result_count" -gt 0 ]; then
                echo "🚨 XSS 발견: ${result_count}개"
                total_xss=$((total_xss + result_count))
                
                # 상세 출력
                jq -r '
                  [if type=="array" then .[] else . end] |
                  map(select(
                    . != null and 
                    . != {} and
                    (.param // .parameter // "") != "" and
                    (.param // .parameter // "") != "unknown"
                  )) |
                  .[] |
                  "  ✅ Parameter: \(.param // .parameter)\n     Payload: \(.payload // "N/A")\n     Evidence: \(.evidence // "N/A")"
                ' "$TEMP_RESULT" 2>/dev/null || echo "  상세 정보 없음"
                
                # JSONL 저장
                jq -c --arg target_url "${url}" '
                  [if type=="array" then .[] else . end] |
                  map(select(
                    . != null and 
                    . != {} and
                    (.param // .parameter // "") != "" and
                    (.param // .parameter // "") != "unknown"
                  )) |
                  .[] |
                  {
                    url: $target_url,
                    parameter: (.param // .parameter),
                    payload: (.payload // ""),
                    evidence: (.evidence // ""),
                    cwe: (.cwe // "CWE-79"),
                    vulnerability: "reflected-xss",
                    severity: "MEDIUM",
                    potential_zero_day: true
                  }
                ' "$TEMP_RESULT" >> "$TEMP_OUTPUT" 2>/dev/null || true
                
                echo "✅ XSS 확인!"
            else
                echo "✅ 안전 (유효한 결과 없음)"
            fi
        else
            echo "⚠️  JSON 파싱 실패"
            echo "원본 내용:"
            head -20 "$TEMP_RESULT"
        fi
    else
        echo "✅ 안전 (결과 파일 없음)"
    fi
    
    rm -f "$TEMP_RESULT"
    echo ""
done

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 최종 JSON 생성 중..."

# 최종 JSON 생성
if [ -s "$TEMP_OUTPUT" ]; then
    jq -s '{
      scan_type: "xss",
      tool: "dalfox",
      target: "'"${TARGET_BASE}"'",
      timestamp: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
      results: .
    }' "$TEMP_OUTPUT" > "${OUTPUT_JSON}"
    
    echo "✅ JSON 생성 완료: $(jq '.results | length' "${OUTPUT_JSON}") 개"
else
    # 빈 결과
    cat > "${OUTPUT_JSON}" << 'JSONEND'
{
  "scan_type": "xss",
  "tool": "dalfox",
  "target": "TARGET_BASE_PLACEHOLDER",
  "timestamp": "TIMESTAMP_PLACEHOLDER",
  "results": []
}
JSONEND
    
    # macOS 호환 sed
    if [[ "$OSTYPE" == "darwin"* ]]; then
        sed -i '' "s|TARGET_BASE_PLACEHOLDER|${TARGET_BASE}|g" "${OUTPUT_JSON}"
        sed -i '' "s|TIMESTAMP_PLACEHOLDER|$(date -u +"%Y-%m-%dT%H:%M:%SZ")|g" "${OUTPUT_JSON}"
    else
        sed -i "s|TARGET_BASE_PLACEHOLDER|${TARGET_BASE}|g" "${OUTPUT_JSON}"
        sed -i "s|TIMESTAMP_PLACEHOLDER|$(date -u +"%Y-%m-%dT%H:%M:%SZ")|g" "${OUTPUT_JSON}"
    fi
    
    echo "⚠️  유효한 결과 없음"
fi

# JSON 검증
if jq empty "${OUTPUT_JSON}" 2>/dev/null; then
    echo "✅ JSON 검증 성공"
    
    # 최종 통계
    final_count=$(jq '.results | length' "${OUTPUT_JSON}")
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📊 최종 통계"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "발견된 XSS: ${final_count}개"
    
    if [ "$final_count" -gt 0 ]; then
        echo ""
        echo "상세:"
        jq -r '.results[] | "  - \(.parameter) at \(.url)"' "${OUTPUT_JSON}"
    fi
else
    echo "❌ JSON 검증 실패!"
    cat "${OUTPUT_JSON}"
fi

rm -f "$TEMP_OUTPUT"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Dalfox 완료"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"