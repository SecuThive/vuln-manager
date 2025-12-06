# 🛡️ Vuln-Manager (Agentless Security Hardening System)

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.95.0-009688.svg)
![MariaDB](https://img.shields.io/badge/MariaDB-10.3+-003545.svg)
![Ollama](https://img.shields.io/badge/Ollama-AI-black.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

> **에이전트 설치 없이(Agentless)** SSH 프로토콜만을 사용하여 리눅스 서버의 취약점을 진단하고, 자동 조치 및 파일 무결성 감시(FIM)를 수행하는 **AI 기반 중앙 보안 관리 시스템**입니다.

---

## 📖 프로젝트 개요 (Overview)

이 프로젝트는 대규모 리눅스 서버 환경에서 **보안 설정(Hardening)**을 효율적으로 관리하기 위해 개발되었습니다. 기존의 에이전트 방식이 가진 리소스 점유 및 호환성 문제를 해결하기 위해 **SSH 기반의 Agentless 아키텍처**를 채택하였으며, **주요정보통신기반시설 기술적 취약점 가이드(U-01 ~ U-70)**를 기준으로 진단 및 조치를 수행합니다.

특히, **Ollama(Local LLM)**를 연동하여 보안 담당자에게 취약점의 위험도와 구체적인 해결 방안을 **AI가 분석하여 제공**하는 기능을 갖추고 있습니다.

## 🚀 주요 기능 (Key Features)

### 1. Agentless Vulnerability Scanning
* **SSH 기반 동작:** 대상 서버에 별도의 에이전트 설치 불필요 (Port 22 사용).
* **컴플라이언스 진단:** KISA 주요정보통신기반시설 가이드 기준 U-01 ~ U-70 항목 자동 진단.
* **전체 진단:** 클릭 한 번으로 등록된 서버의 모든 보안 항목 일괄 점검.

### 2. Smart Remediation (동적 조치)
* **파라미터 튜닝:** 단순히 On/Off가 아닌, **패스워드 길이, 세션 타임아웃 시간** 등을 관리자가 직접 설정하여 조치 가능.
* **안전한 조치:** 서비스 중단을 야기할 수 있는 위험 항목(계정 삭제 등)은 **수동 가이드(Manual Guide)** 제공.
* **멱등성 보장:** 여러 번 조치를 수행해도 설정 파일이 깨지지 않도록 `sed` 및 정규식 기반의 안전한 스크립트 설계.

### 3. File Integrity Monitoring (FIM)
* **실시간 무결성 감시:** 핵심 시스템 파일(`/etc/passwd`, `/bin/login` 등)의 해시(Hash) 변경 감지.
* **변경 승인 프로세스:** 정상적인 패치나 작업으로 인한 변경 사항을 승인(Acknowledge)하여 새로운 기준값(Baseline)으로 갱신 가능.

### 4. AI Security Analyst (Ollama Integration)
* **AI 기반 분석:** 발견된 취약점에 대해 **"왜 위험한지", "어떻게 조치해야 하는지"**를 Local LLM(Llama3)이 분석하여 설명.
* **데이터 보안:** 외부 API를 사용하지 않고 사내망(On-Premise)에 구축된 Ollama를 사용하여 데이터 유출 방지.

### 5. Secure Dashboard & Management
* **사용자 인증:** JWT 기반의 로그인/로그아웃 및 세션 관리 (Bcrypt 암호화).
* **영구 저장:** MariaDB를 연동하여 자산 정보 및 진단 이력 영구 보관.
* **직관적인 UI:** 서버 상태, 취약점 현황, 조치 내역을 한눈에 파악 가능한 대시보드 제공.

---

## 🛠️ 기술 스택 (Tech Stack)

| 구분 | 기술 (Technology) | 설명 |
| :--- | :--- | :--- |
| **Backend** | Python, FastAPI | 비동기 처리 및 RESTful API 서버 구축 |
| **Database** | MariaDB (MySQL) | 자산 정보, 진단 결과, FIM 데이터 저장 (utf8mb4) |
| **Infra** | SSH, Paramiko | Agentless 원격 제어 및 명령어 실행 |
| **AI Engine** | Ollama (Llama3) | 취약점 분석 및 가이드 생성 (Local LLM) |
| **Frontend** | HTML5, JavaScript | Jinja2 템플릿 엔진을 활용한 동적 렌더링 |
| **Security** | Passlib, python-jose | JWT 토큰 발급 및 비밀번호 해시 암호화 |
| **OS** | Rocky Linux 8.10 | 서버 운영체제 |

---

## ⚙️ 설치 및 실행 (Installation)

### 1. 환경 설정 (Prerequisites)
* Python 3.9+
* MariaDB Server
* Ollama (AI 기능 사용 시)

### 2. 저장소 클론 (Clone)
```bash
git clone [https://github.com/your-username/vuln-manager.git](https://github.com/your-username/vuln-manager.git)
cd vuln-manager
