#!/bin/bash
# 6_generate_json.sh - 모든 스캔 결과를 semgrep 형태로 통합

set -e

RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/dast_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 JSON 통합 (semgrep 형태)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

WPSCAN_JSON="${RESULTS_DIR}/wpscan_results.json"
NUCLEI_JSON="${RESULTS_DIR}/nuclei_results.json"
WFUZZ_JSON="${RESULTS_DIR}/wfuzz_results.json"
DALFOX_JSON="${RESULTS_DIR}/dalfox_results.json"
SQLMAP_JSON="${RESULTS_DIR}/sqlmap_results.json"

# 임시 파일 사용
TEMP_RESULTS="/tmp/dast_results_$$.json"
> "$TEMP_RESULTS"  # 초기화

# WPScan 결과 변환
if [ -f "${WPSCAN_JSON}" ]; then
    echo "  📝 WPScan 결과 통합 중..."
    
    jq -r '.plugins // {} | to_entries[] | 
      .key as $plugin | 
      .value.vulnerabilities[]? | 
      {
        check_id: "wpscan.known-cve",
        path: $plugin,
        start: {line: 0, col: 0},
        end: {line: 0, col: 0},
        extra: {
          message: .title,
          metadata: {
            tool: "wpscan",
            cve: (.references.cve[0] // "N/A"),
            plugin: $plugin,
            zero_day: false
          },
          severity: (if .cvss.score >= 9 then "CRITICAL" 
                     elif .cvss.score >= 7 then "HIGH"
                     elif .cvss.score >= 4 then "MEDIUM"
                     else "LOW" end),
          fingerprint: ("wpscan-" + (.references.cve[0] // "N/A")),
          lines: "N/A (Dynamic Analysis)"
        }
      }' "${WPSCAN_JSON}" 2>/dev/null >> "$TEMP_RESULTS" || true
fi

# Nuclei 결과 변환
if [ -f "${NUCLEI_JSON}" ] && [ -s "${NUCLEI_JSON}" ]; then
    echo "  📝 Nuclei 결과 통합 중..."
    
    jq -c '{
      check_id: ("nuclei." + .["template-id"]),
      path: .["matched-at"],
      start: {line: 0, col: 0},
      end: {line: 0, col: 0},
      extra: {
        message: .info.name,
        metadata: {
          tool: "nuclei",
          template_id: .["template-id"],
          zero_day: false
        },
        severity: (.info.severity | ascii_upcase),
        fingerprint: ("nuclei-" + .["template-id"]),
        lines: "N/A (Dynamic Analysis)"
      }
    }' "${NUCLEI_JSON}" 2>/dev/null >> "$TEMP_RESULTS" || true
fi

# wfuzz 결과 변환
if [ -f "${WFUZZ_JSON}" ]; then
    echo "  📝 wfuzz 결과 통합 중..."
    
    jq -c '.results[]? | {
      check_id: "dast.sqli-time-based",
      path: .url,
      start: {line: 0, col: 0},
      end: {line: 0, col: 0},
      extra: {
        message: ("Time-based SQL Injection detected in parameter '" + .parameter + "' (Response: " + .response_time + ")"),
        metadata: {
          tool: "wfuzz",
          cwe: "CWE-89",
          parameter: .parameter,
          payload: .payload,
          response_time: .response_time,
          zero_day: true
        },
        severity: "HIGH",
        fingerprint: ("sqli-" + .parameter),
        lines: "N/A (Dynamic Analysis)"
      }
    }' "${WFUZZ_JSON}" 2>/dev/null >> "$TEMP_RESULTS" || true
fi

# Dalfox 결과 변환
if [ -f "${DALFOX_JSON}" ]; then
    echo "  📝 Dalfox 결과 통합 중..."
    
    jq -c '.results[]? | {
      check_id: "dast.xss-reflected",
      path: .url,
      start: {line: 0, col: 0},
      end: {line: 0, col: 0},
      extra: {
        message: ("Reflected XSS detected in parameter '" + .parameter + "'"),
        metadata: {
          tool: "dalfox",
          cwe: "CWE-79",
          parameter: .parameter,
          payload: .payload,
          zero_day: false
        },
        severity: "MEDIUM",
        fingerprint: ("xss-" + .parameter),
        lines: "N/A (Dynamic Analysis)"
      }
    }' "${DALFOX_JSON}" 2>/dev/null >> "$TEMP_RESULTS" || true
fi

# SQLMap 결과 변환
if [ -f "${SQLMAP_JSON}" ]; then
    echo "  📝 SQLMap 결과 통합 중..."
    
    jq -c '.results[]? | {
      check_id: "dast.sqli-confirmed",
      path: .url,
      start: {line: 0, col: 0},
      end: {line: 0, col: 0},
      extra: {
        message: ("SQL Injection confirmed by SQLMap in parameter '" + .parameter + "' (DBMS: " + .dbms + ")"),
        metadata: {
          tool: "sqlmap",
          cwe: "CWE-89",
          parameter: .parameter,
          dbms: .dbms,
          exploitable: true,
          zero_day: true
        },
        severity: "CRITICAL",
        fingerprint: ("sqli-confirmed-" + .parameter),
        lines: "N/A (Dynamic Analysis)"
      }
    }' "${SQLMAP_JSON}" 2>/dev/null >> "$TEMP_RESULTS" || true
fi

# 최종 JSON 생성
echo "  ✅ 최종 JSON 생성 중..."

cat > "${OUTPUT_JSON}" << 'JSON_START'
{
  "version": "1.0.0",
  "scan_type": "DAST",
  "tool": "wpscan + nuclei + wfuzz + dalfox + sqlmap",
  "timestamp": "JSON_START
echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "${OUTPUT_JSON}"
cat >> "${OUTPUT_JSON}" << JSON_MID
",
  "target": "${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}",
  "results": [
JSON_MID

# 임시 결과 파일을 배열 형태로 삽입
if [ -s "$TEMP_RESULTS" ]; then
    # jq로 각 줄을 읽어서 배열로 만들기
    jq -s '.' "$TEMP_RESULTS" | jq '.[]' | jq -s '.' | jq '.[]' | \
    awk 'NR>1{print ","} {printf "%s", $0}' >> "${OUTPUT_JSON}"
fi

cat >> "${OUTPUT_JSON}" << 'JSON_END'
  ],
  "errors": [],
  "paths": {
    "scanned": ["
JSON_END
echo "${TARGET_BASE:-http://localhost:8888/wordpress-zeroday}\"" >> "${OUTPUT_JSON}"
cat >> "${OUTPUT_JSON}" << 'JSON_FINAL'
  ]
}
JSON_FINAL

rm -f "$TEMP_RESULTS"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 최종 결과"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

total=$(jq '.results | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)
zero_day=$(jq '[.results[] | select(.extra.metadata.zero_day == true)] | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)
critical=$(jq '[.results[] | select(.extra.severity == "CRITICAL")] | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)
high=$(jq '[.results[] | select(.extra.severity == "HIGH")] | length' "${OUTPUT_JSON}" 2>/dev/null || echo 0)

echo "📄 파일: ${OUTPUT_JSON}"
echo ""
echo "통계:"
echo "  총 취약점: ${total}개"
echo "  🎯 제로데이: ${zero_day}개"
echo "  🔴 Critical: ${critical}개"
echo "  🟠 High: ${high}개"
echo ""

if [ "$zero_day" -gt 0 ]; then
    echo "🎯 제로데이 목록:"
    jq -r '.results[] | select(.extra.metadata.zero_day == true) | "  - \(.extra.metadata.parameter // .check_id): \(.extra.message)"' "${OUTPUT_JSON}" 2>/dev/null || true
fi