# reset_admin.py
from passlib.context import CryptContext
import db  # 우리가 만든 db.py 모듈

# 암호화 설정
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def reset_admin():
    username = "admin"
    password = "admin123"  # 원하는 비밀번호
    
    print(f"[*] '{username}' 계정 비밀번호를 '{password}'로 재설정합니다...")
    
    try:
        # 1. 현재 라이브러리로 비밀번호 해시 생성
        hashed_password = pwd_context.hash(password)
        
        # 2. DB 연결
        conn = db.get_conn()
        with conn.cursor() as cursor:
            # 기존 계정 삭제 (충돌 방지)
            cursor.execute("DELETE FROM users WHERE username=%s", (username,))
            
            # 새 비밀번호로 계정 생성
            sql = "INSERT INTO users (username, password_hash) VALUES (%s, %s)"
            cursor.execute(sql, (username, hashed_password))
        
        conn.commit()
        conn.close()
        print("✅ 성공! 로그인해보세요.")
        print(f"👉 ID: {username}")
        print(f"👉 PW: {password}")
        
    except Exception as e:
        print(f"❌ 오류 발생: {e}")
        print("Tip: db.py 파일의 DB 비밀번호가 맞는지 확인해보세요.")

if __name__ == "__main__":
    reset_admin()
