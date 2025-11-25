#!/usr/bin/env python3
import json
import sys
import os
import requests
from pathlib import Path
from datetime import datetime

def validate_json(filepath):
    """JSON 파일 검증"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return True, data, None
    except json.JSONDecodeError as e:
        return False, None, f"JSON 파싱 오류: {e}"
    except Exception as e:
        return False, None, f"파일 읽기 오류: {e}"

def upload_results(filepath, dashboard_url):
    """결과를 대시보드로 업로드"""
    
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("📤 DAST 결과 업로드")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print(f"파일: {filepath}")
    print()
    
    # JSON 검증
    is_valid, data, error = validate_json(filepath)
    
    if not is_valid:
        print(f"⚠️  {error}")
        
        # 기본 JSON 생성
        print("📝 기본 JSON 생성 중...")
        data = {
            "version": "1.0.0",
            "scan_type": "DAST",
            "tool": "combined",
            "timestamp": datetime.now().isoformat(),
            "target": "http://13.209.62.212",
            "results": [],
            "errors": [error],
            "paths": {"scanned": []}
        }
        
        # 저장
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print("✅ 기본 JSON 저장 완료")
    else:
        print(f"✅ JSON 유효성 검증 통과")
    
    # 파일 크기
    file_size = os.path.getsize(filepath)
    print(f"📦 파일 크기: {file_size:,} bytes")
    
    # 통계
    result_count = len(data.get('results', []))
    print(f"📊 취약점 개수: {result_count}개")
    print()
    
    # 날짜가 포함된 파일명 생성
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    original_filename = os.path.basename(filepath)
    base_name = os.path.splitext(original_filename)[0]
    new_filename = f"{base_name}_{timestamp}.json"
    
    print(f"📝 업로드 파일명: {new_filename}")
    print()
    
    # 업로드
    try:
        print("🚀 서버로 전송 중...")
        print(f"   대상: {dashboard_url}")
        print(f"   방식: multipart/form-data (파일 업로드)")
        print()
        
        # 파일을 multipart/form-data로 업로드
        with open(filepath, 'rb') as f:
            files = {
                'file': (
                    new_filename,           # 날짜 포함 파일명!
                    f,
                    'application/json'
                )
            }
            
            response = requests.post(
                dashboard_url,
                files=files,
                timeout=30
            )
        
        if response.status_code == 200:
            print("✅ 업로드 성공!")
            try:
                result = response.json()
                print(f"   서버 응답: {result}")
            except:
                print(f"   응답: {response.text[:200]}")
        else:
            print(f"⚠️ 업로드 실패: {response.status_code}")
            try:
                error_detail = response.json()
                print(f"   에러: {error_detail}")
            except:
                print(f"   응답: {response.text[:200]}")
        
        print()
        return response.status_code == 200
        
    except requests.exceptions.Timeout:
        print("❌ 타임아웃! 서버 응답 없음")
        return False
    except requests.exceptions.ConnectionError:
        print("❌ 연결 실패! 서버 접근 불가")
        return False
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    if len(sys.argv) < 2:
        print("사용법: python3 7_upload.py <results_file>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"❌ 파일 없음: {filepath}")
        sys.exit(1)
    
    # 환경변수에서 대시보드 URL 가져오기
    dashboard_url = os.environ.get('DASHBOARD_URL', 'http://3.36.21.85:5000/upload')
    
    success = upload_results(filepath, dashboard_url)
    
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    if success:
        print("✅ 성공!")
    else:
        print("❌ 실패!")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()