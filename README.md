# 🛡️ Agentless Vulnerability Management System

에이전트 설치 없이 SSH 프로토콜만을 사용하여 리눅스 서버의 취약점을 진단하고 조치하는 중앙 관리 시스템입니다.

## 🚀 주요 기능
* **에이전트리스(Agentless):** 타겟 서버에 별도 설치 없이 SSH(22번 포트)로만 동작
* **취약점 진단 및 조치:** 주요정보통신기반시설 가이드 기준 U-01~U-70 항목 진단 및 자동/수동 조치
* **파일 무결성 감시 (FIM):** 핵심 시스템 파일 변조 실시간 탐지 및 승인 프로세스
* **동적 파라미터 조치:** 패스워드 복잡성, 타임아웃 등 설정값 커스터마이징 가능
* **대시보드:** 전체 서버 상태 모니터링 및 일괄 진단 기능

## 🛠️ 기술 스택
* **Backend:** Python 3.9, FastAPI
* **Database:** MariaDB (MySQL)
* **Frontend:** HTML5, CSS3, JavaScript (Jinja2 Templates)
* **Infrastructure:** Rocky Linux 8.10

## 📦 설치 및 실행 방법

1. 저장소 클론
   \`\`\`bash
   git clone https://github.com/본인아이디/vuln-manager.git
   \`\`\`

2. 필수 라이브러리 설치
   \`\`\`bash
   pip install -r requirements.txt
   \`\`\`

3. 환경 변수 설정 (.env 생성)
   \`\`\`ini
   DB_PASSWORD=your_password
   SECRET_KEY=your_secret
   \`\`\`

4. 실행
   \`\`\`bash
   uvicorn main:app --host 0.0.0.0 --port 8000
   \`\`\`

## 📸 스크린샷

