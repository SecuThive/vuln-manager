import requests
import json

# Ollama API 설정
OLLAMA_URL = "http://localhost:11434/api/generate"

# [중요] 모델이 작을수록 프롬프트가 구체적이어야 합니다.
# 만약 서버 사양이 허락한다면 'qwen2.5:3b' 모델을 강력 추천합니다.
MODEL_NAME = "qwen2.5:1.5b" 

def ask_ai(vuln_name, description, current_output, target_os="Rocky Linux 8"):
    
    # [핵심] Few-Shot Prompting: AI에게 정답 샘플을 학습시킴
    prompt = f"""
    당신은 리눅스(Rocky Linux 8) 보안 침해 사고 대응 전문가입니다.
    사용자가 제공하는 취약점 정보를 분석하여, 반드시 아래 [출력 양식]에 맞춰 답변하세요.
    서론이나 인사말은 생략하고 본론만 출력하세요.

    [학습 예시 1]
    입력: 취약점 'SSH Root 접속 허용', 상태 'PermitRootLogin yes'
    출력:
    **위험한 이유**
    Root 계정으로 직접 로그인이 허용되면, 공격자가 무차별 대입 공격(Brute Force)을 통해 관리자 권한을 바로 탈취할 수 있습니다.

    **조치방법**
    명령어 : sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
     - SSH 설정 파일에서 Root 접속을 차단하도록 수정합니다.
    명령어 : systemctl reload sshd
     - 변경된 설정을 적용하기 위해 서비스를 재시작합니다.

    [학습 예시 2]
    입력: 취약점 '불필요한 계정 존재', 상태 'lp, uucp 계정 발견'
    출력:
    **위험한 이유**
    시스템 운영에 불필요한 기본 계정이 활성화되어 있으면, 공격자가 이를 악용하여 권한 상승이나 우회 공격의 통로로 사용할 수 있습니다.

    **조치방법**
    명령어 : userdel lp
     - 불필요한 lp 계정을 시스템에서 삭제합니다.
    명령어 : userdel uucp
     - 불필요한 uucp 계정을 시스템에서 삭제합니다.

    --------------------------------------------------
    [실제 분석 요청]
    - 대상 OS: {target_os}
    - 취약점명: {vuln_name}
    - 설명: {description}
    - 현재 상태: {current_output}

    위 정보를 바탕으로 [출력 양식]대로 답변을 작성하세요.
    """

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,  # 0에 가까울수록 창의성을 죽이고 정확한 팩트만 말함
            "top_p": 0.5,        # 엉뚱한 단어 선택 배제
            "num_predict": 512   # 답변 길이 제한
        }
    }
    
    try:
        # 타임아웃을 5분으로 설정 (모델이 느릴 수 있음)
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        
        if response.status_code == 200:
            return response.json().get("response", "AI 응답 없음")
        else:
            return f"AI 서버 에러: {response.status_code} - {response.text}"
            
    except Exception as e:
        return f"AI 연결 실패: {str(e)}"


# [ai_manager.py] 기존 코드 아래에 추가
def analyze_code(file_path, file_content):
    if len(file_content) > 2000: file_content = file_content[:2000] + "\n...(생략)..."
    
    # [프롬프트 대폭 강화]
    prompt = f"""
    당신은 침해사고 대응 전문가입니다. 아래 PHP 코드가 '악성 웹쉘'인지 '정상 관리 도구'인지 정밀 분석하세요.

    [분석 파일]: {file_path}
    [소스 코드]:
    ```php
    {file_content}
    ```

    [판단 기준 (매우 중요)]
    1. system, shell_exec, eval 함수가 있어도, **명령어가 하드코딩(고정) 되어 있으면 '정상(관리도구)'**로 판단하세요. (예: system("df -h"))
    2. 반대로, **외부 입력($_GET, $_POST)을 검증 없이 실행하면 '악성(웹쉘)'**입니다. (예: system($_GET['cmd']))
    3. base64_decode가 있어도, 단순 데이터 처리는 정상입니다. 실행(eval)과 결합될 때만 위험합니다.

    [결과 출력 양식]
    **판정:** [정상 / 악성 / 의심] 중 택 1
    **위험도:** 0~100점
    **분석:** (코드의 의도와 위험/안전 판단 이유를 명확히 설명)
    **권고:** (삭제 필요 여부)
    """
    
    payload = {
        "model": MODEL_NAME, "prompt": prompt, "stream": False,
        "options": {"temperature": 0.1} # 창의성 최소화 (논리적 판단 유도)
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=300)
        if response.status_code == 200: return response.json().get("response", "응답 없음")
        return f"AI 에러: {response.status_code}"
    except Exception as e: return f"AI 연결 실패: {str(e)}"
