#!/bin/bash
set -e

RESULTS_DIR="results"
OUTPUT_JSON="${RESULTS_DIR}/dast_results.json"

mkdir -p "${RESULTS_DIR}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 JSON 통합 (semgrep 형태)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# 임시 배열 파일
TEMP_RESULTS="/tmp/dast_temp_results_$$.json"
echo '[]' > "$TEMP_RESULTS"

# 1. Nuclei 변환
echo "  📝 Nuclei 결과 통합 중..."
if [ -f "${RESULTS_DIR}/nuclei_results.json" ] && [ -s "${RESULTS_DIR}/nuclei_results.json" ]; then
    NUCLEI_CONVERTED="/tmp/nuclei_converted_$$.json"
    
    jq -s 'map({
      check_id: ("nuclei." + .["template-id"]),
      path: (.["matched-at"] // "N/A"),
      start: {line: 0, col: 0},
      end: {line: 0, col: 0},
      extra: {
        message: (.info.name // "Unknown vulnerability"),
        metadata: {
          tool: "nuclei",
          template_id: (.["template-id"] // "unknown"),
          zero_day: false
        },
        severity: ((.info.severity // "info") | ascii_upcase),
        fingerprint: ("nuclei-" + (.["template-id"] // "unknown")),
        lines: "N/A (Dynamic Analysis)"
      }
    })' "${RESULTS_DIR}/nuclei_results.json" > "$NUCLEI_CONVERTED" 2>/dev/null || echo '[]' > "$NUCLEI_CONVERTED"
    
    jq -s '.[0] + .[1]' "$TEMP_RESULTS" "$NUCLEI_CONVERTED" > /tmp/temp_merge.json
    mv /tmp/temp_merge.json "$TEMP_RESULTS"
    rm -f "$NUCLEI_CONVERTED"
fi

# 2. WPScan 변환
echo "  📝 WPScan 결과 통합 중..."
if [ -f "${RESULTS_DIR}/wpscan_results.json" ] && [ -s "${RESULTS_DIR}/wpscan_results.json" ]; then
    WPSCAN_CONVERTED="/tmp/wpscan_converted_$$.json"
    
    jq '[.plugins // {} | to_entries[] | .value as $plugin | .key as $pname | 
      ($plugin.vulnerabilities // [])[] | {
        check_id: ("wpscan.cve." + (.title // "unknown" | gsub("[^a-zA-Z0-9]"; "-"))),
        path: ("Plugin: " + $pname),
        start: {line: 0, col: 0},
        end: {line: 0, col: 0},
        extra: {
          message: (.title // "Unknown vulnerability"),
          metadata: {
            tool: "wpscan",
            plugin: $pname,
            vuln_type: (.vuln_type // "unknown"),
            zero_day: false
          },
          severity: "HIGH",
          fingerprint: ("wpscan-" + ($pname // "unknown")),
          lines: "N/A (Dynamic Analysis)"
        }
      }
    ]' "${RESULTS_DIR}/wpscan_results.json" > "$WPSCAN_CONVERTED" 2>/dev/null || echo '[]' > "$WPSCAN_CONVERTED"
    
    jq -s '[.[0][], .[1][]]' "$TEMP_RESULTS" "$WPSCAN_CONVERTED" > /tmp/temp_merge.json
    mv /tmp/temp_merge.json "$TEMP_RESULTS"
    rm -f "$WPSCAN_CONVERTED"
fi

# 3. wfuzz 변환
echo "  📝 wfuzz 결과 통합 중..."
if [ -f "${RESULTS_DIR}/wfuzz_results.json" ] && [ -s "${RESULTS_DIR}/wfuzz_results.json" ]; then
    WFUZZ_CONVERTED="/tmp/wfuzz_converted_$$.json"
    
    jq '[.results[] | {
      check_id: ("wfuzz.sqli." + (.parameter // "unknown")),
      path: (.url // "N/A"),
      start: {line: 0, col: 0},
      end: {line: 0, col: 0},
      extra: {
        message: ("Time-based SQL Injection in parameter: " + (.parameter // "unknown")),
        metadata: {
          tool: "wfuzz",
          parameter: (.parameter // "unknown"),
          payload: (.payload // ""),
          response_time: (.response_time // "unknown"),
          zero_day: (.potential_zero_day // true)
        },
        severity: (.severity // "HIGH"),
        fingerprint: ("wfuzz-" + (.parameter // "unknown")),
        lines: "N/A (Dynamic Analysis)"
      }
    }]' "${RESULTS_DIR}/wfuzz_results.json" > "$WFUZZ_CONVERTED" 2>/dev/null || echo '[]' > "$WFUZZ_CONVERTED"
    
    jq -s '[.[0][], .[1][]]' "$TEMP_RESULTS" "$WFUZZ_CONVERTED" > /tmp/temp_merge.json
    mv /tmp/temp_merge.json "$TEMP_RESULTS"
    rm -f "$WFUZZ_CONVERTED"
fi

# 4. Dalfox 변환
echo "  📝 Dalfox 결과 통합 중..."
if [ -f "${RESULTS_DIR}/dalfox_results.json" ] && [ -s "${RESULTS_DIR}/dalfox_results.json" ]; then
    DALFOX_CONVERTED="/tmp/dalfox_converted_$$.json"
    
    jq '[.results[] | {
      check_id: ("dalfox.xss." + (.parameter // "unknown")),
      path: (.url // "N/A"),
      start: {line: 0, col: 0},
      end: {line: 0, col: 0},
      extra: {
        message: ("XSS vulnerability in parameter: " + (.parameter // "unknown")),
        metadata: {
          tool: "dalfox",
          parameter: (.parameter // "unknown"),
          payload: (.payload // ""),
          zero_day: (.potential_zero_day // false)
        },
        severity: (.severity // "MEDIUM"),
        fingerprint: ("dalfox-" + (.parameter // "unknown")),
        lines: "N/A (Dynamic Analysis)"
      }
    }]' "${RESULTS_DIR}/dalfox_results.json" > "$DALFOX_CONVERTED" 2>/dev/null || echo '[]' > "$DALFOX_CONVERTED"
    
    jq -s '[.[0][], .[1][]]' "$TEMP_RESULTS" "$DALFOX_CONVERTED" > /tmp/temp_merge.json
    mv /tmp/temp_merge.json "$TEMP_RESULTS"
    rm -f "$DALFOX_CONVERTED"
fi

# 5. SQLMap 변환
echo "  📝 SQLMap 결과 통합 중..."
if [ -f "${RESULTS_DIR}/sqlmap_results.json" ] && [ -s "${RESULTS_DIR}/sqlmap_results.json" ]; then
    SQLMAP_CONVERTED="/tmp/sqlmap_converted_$$.json"
    
    jq '[.results[] | {
      check_id: ("sqlmap.sqli." + (.parameter // "unknown")),
      path: (.url // "N/A"),
      start: {line: 0, col: 0},
      end: {line: 0, col: 0},
      extra: {
        message: ("Confirmed SQL Injection in parameter: " + (.parameter // "unknown")),
        metadata: {
          tool: "sqlmap",
          parameter: (.parameter // "unknown"),
          technique: (.technique // "unknown"),
          confirmed: (.confirmed // true),
          zero_day: (.potential_zero_day // true)
        },
        severity: (.severity // "CRITICAL"),
        fingerprint: ("sqlmap-" + (.parameter // "unknown")),
        lines: "N/A (Dynamic Analysis)"
      }
    }]' "${RESULTS_DIR}/sqlmap_results.json" > "$SQLMAP_CONVERTED" 2>/dev/null || echo '[]' > "$SQLMAP_CONVERTED"
    
    jq -s '[.[0][], .[1][]]' "$TEMP_RESULTS" "$SQLMAP_CONVERTED" > /tmp/temp_merge.json
    mv /tmp/temp_merge.json "$TEMP_RESULTS"
    rm -f "$SQLMAP_CONVERTED"
fi

echo "  ✅ 최종 JSON 생성 중..."

# 최종 JSON 생성 (완벽한 문법)
jq '{
  version: "1.0.0",
  scan_type: "DAST",
  tool: "nuclei + wpscan + wfuzz + dalfox + sqlmap",
  timestamp: (now | strftime("%Y-%m-%dT%H:%M:%SZ")),
  target: "'"${TARGET_BASE}"'",
  results: .,
  errors: [],
  paths: {scanned: []}
}' "$TEMP_RESULTS" > "$OUTPUT_JSON"

# JSON 검증
if jq empty "$OUTPUT_JSON" 2>/dev/null; then
    echo "  ✅ JSON 검증 성공"
else
    echo "  ❌ JSON 검증 실패! 기본 JSON 생성..."
    cat > "$OUTPUT_JSON" << FALLBACK
{
  "version": "1.0.0",
  "scan_type": "DAST",
  "tool": "combined",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "target": "${TARGET_BASE}",
  "results": [],
  "errors": ["JSON generation failed"],
  "paths": {"scanned": []}
}
FALLBACK
fi

rm -f "$TEMP_RESULTS" /tmp/*_converted_$$.json

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 최종 결과"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📄 파일: ${OUTPUT_JSON}"
echo ""

if [ -f "$OUTPUT_JSON" ]; then
    echo "통계:"
    jq -r '
      "  총 취약점: \(.results | length)개",
      "  🎯 제로데이: \([.results[] | select(.extra.metadata.zero_day == true)] | length)개",
      "  🔴 Critical: \([.results[] | select(.extra.severity == "CRITICAL")] | length)개",
      "  🟠 High: \([.results[] | select(.extra.severity == "HIGH")] | length)개",
      "  🟡 Medium: \([.results[] | select(.extra.severity == "MEDIUM")] | length)개",
      "  🔵 Info: \([.results[] | select(.extra.severity == "INFO")] | length)개"
    ' "$OUTPUT_JSON" 2>/dev/null || echo "  통계 생성 실패"
fi

echo ""