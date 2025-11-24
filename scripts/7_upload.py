#!/usr/bin/env python3
# 7_upload.py - 스캔 결과를 대시보드 서버에 업로드

import requests
import os
import sys
import json

# --- 설정 ---
# 환경변수에서 읽기 (없으면 기본값)
UPLOAD_URL = os.getenv('DASHBOARD_URL', 'http://3.36.21.85:5000/upload')
RESULT_FILE = "results/dast_results.json"

def upload_to_dashboard(file_path):
    """스캔 결과 JSON 파일을 대시보드 서버에 업로드"""
    
    if not os.path.exists(file_path):
        print(f"❌ 파일 없음: {file_path}")
        return False
    
    file_size = os.path.getsize(file_path)
    print(f"📦 파일 크기: {file_size:,} bytes")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            result_count = len(data.get('results', []))
            print(f"📊 취약점: {result_count}개")
    except json.JSONDecodeError as e:
        print(f"⚠️  JSON 오류: {e}")
    
    print(f"🚀 서버로 전송 중...")
    print(f"   대상: {UPLOAD_URL}")
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'application/json')}
            response = requests.post(UPLOAD_URL, files=files, timeout=30)
        
        if response.status_code == 200:
            print("✅ 업로드 성공!")
            try:
                print(f"   응답: {response.json()}")
            except:
                print(f"   응답: {response.text}")
            return True
        else:
            print(f"⚠️ 업로드 실패: {response.status_code}")
            print(f"   {response.text}")
            return False
            
    except requests.exceptions.Timeout:
        print("❌ 타임아웃 (30초)")
        return False
        
    except requests.exceptions.ConnectionError:
        print("❌ 연결 오류")
        print(f"   서버: {UPLOAD_URL}")
        print("   - 서버 실행 중인지 확인")
        print("   - 방화벽 설정 확인")
        return False
        
    except Exception as e:
        print(f"❌ 오류: {e}")
        return False

def main():
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("📤 DAST 결과 업로드")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("")
    
    file_path = sys.argv[1] if len(sys.argv) > 1 else RESULT_FILE
    print(f"파일: {file_path}")
    print("")
    
    success = upload_to_dashboard(file_path)
    
    print("")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    
    if success:
        print("✅ 완료!")
        sys.exit(0)
    else:
        print("❌ 실패!")
        sys.exit(1)

if __name__ == "__main__":
    main()