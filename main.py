import os
from dotenv import load_dotenv
import paramiko
from fastapi import FastAPI, Request, Form, Depends, status
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel
from typing import Optional, Dict
import datetime
import traceback
import json
from passlib.context import CryptContext
from jose import JWTError, jwt

# [중요] 모듈 임포트
from scripts_db import VULN_SCRIPTS 
import db 
import ai_manager  # <--- 이 부분이 에러 원인이었음 (파일 생성 필수)

# --- 보안 설정 ---
load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "default_unsafe_key") # 환경변수 사용
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI()
templates = Jinja2Templates(directory="templates")

# 데이터 모델
class FixRequest(BaseModel):
    params: Dict[str, str] = {}

# 인증 함수
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)
def create_token(data: dict): return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
async def get_current_user(request: Request):
    token = request.cookies.get("access_token")
    if not token: return None
    try: return jwt.decode(token.split(" ")[1], SECRET_KEY, algorithms=[ALGORITHM]).get("sub")
    except: return None

# SSH 클래스
class SSHManager:
    def __init__(self, ip, user, password):
        self.ip=ip; self.user=user; self.password=password; self.client=None
    def connect(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try: self.client.connect(self.ip, username=self.user, password=self.password, port=22, timeout=5); return True
        except: return False
    def run_command(self, cmd):
        if not self.client and not self.connect(): return -999, "Connect Fail"
        stdin, stdout, stderr = self.client.exec_command(cmd)
        return stdout.channel.recv_exit_status(), stdout.read().decode().strip() or stderr.read().decode().strip()
    def close(self):
        if self.client: self.client.close()

# --- Routes ---

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(request: Request, username: str=Form(...), password: str=Form(...)):
    user = db.get_user(username)
    if not user or not verify_password(password, user['password_hash']):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Login Failed"})
    token = create_token({"sub": username})
    res = RedirectResponse("/", status_code=303)
    res.set_cookie("access_token", f"Bearer {token}", httponly=True)
    return res

@app.get("/logout")
async def logout():
    res = RedirectResponse("/login", status_code=303)
    res.delete_cookie("access_token")
    return res

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    user = await get_current_user(request)
    if not user: return RedirectResponse("/login")
    return templates.TemplateResponse("server_list.html", {"request": request, "servers": db.get_servers(), "user": user})

@app.get("/server/{ip}", response_class=HTMLResponse)
async def server_detail(request: Request, ip: str):
    user = await get_current_user(request)
    if not user: return RedirectResponse("/login")
    target = db.get_servers().get(ip)
    if not target: return HTMLResponse("Not Found", status_code=404)
    
    # 입력 필드 JSON 변환 (프론트엔드 오류 방지)
    input_map = {code: script.get("inputs", []) for code, script in VULN_SCRIPTS.items()}
    input_map_json = json.dumps(input_map)

    return templates.TemplateResponse("server_detail.html", {
        "request": request, 
        "server": target, 
        "vuln_list": VULN_SCRIPTS, 
        "fim_list": db.get_fim_list(ip), 
        "user": user,
        "input_map_json": input_map_json
    })

@app.post("/add")
async def add_server(request: Request, ip: str=Form(...), username: str=Form(...), password: str=Form(...)):
    if not await get_current_user(request): return {"success": False, "msg": "Auth Required"}
    ssh = SSHManager(ip, username, password)
    if ssh.connect():
        ssh.close(); db.add_server(ip, username, password)
        return {"success": True, "msg": f"✅ {ip} 등록 완료"}
    return {"success": False, "msg": "❌ 연결 실패"}

@app.post("/scan/{ip}/{code}")
async def scan_vuln(request: Request, ip: str, code: str):
    if not await get_current_user(request): return {"error": "Auth Required"}
    auth = db.get_server_auth(ip)
    ssh = SSHManager(ip, auth['username'], auth['password'])
    status, out = ssh.run_command(VULN_SCRIPTS[code]['check_cmd'])
    ssh.close()
    is_vuln = (status == 0)
    msg = f"⚠️ 취약:\n{out}" if is_vuln else f"✅ 양호:\n{out}"
    if status not in [0,1]: msg = f"❌ 에러:\n{out}"; is_vuln = False
    db.save_scan_result(ip, code, msg, is_vuln)
    return {"status": msg, "vulnerable": is_vuln, "last_check": str(datetime.datetime.now())}

@app.post("/scan_all/{ip}")
async def scan_all(request: Request, ip: str):
    if not await get_current_user(request): return {"success": False}
    auth = db.get_server_auth(ip)
    ssh = SSHManager(ip, auth['username'], auth['password'])
    if not ssh.connect(): return {"success": False, "error": "Connect Fail"}
    results = {}
    for code, script in VULN_SCRIPTS.items():
        status, out = ssh.run_command(script['check_cmd'])
        is_vuln = (status == 0)
        msg = f"⚠️ 취약:\n{out}" if is_vuln else f"✅ 양호:\n{out}"
        if status not in [0,1]: msg = f"❌ 에러:\n{out}"; is_vuln = False
        db.save_scan_result(ip, code, msg, is_vuln)
        results[code] = {"vulnerable": is_vuln, "last_check": str(datetime.datetime.now()), "status": msg}
    ssh.close()
    return {"success": True, "results": results}

@app.post("/fix/{ip}/{code}")
async def fix_vuln(request: Request, ip: str, code: str, req: FixRequest):
    if not await get_current_user(request): return {"result": "Auth Required"}
    auth = db.get_server_auth(ip)
    ssh = SSHManager(ip, auth['username'], auth['password'])
    script = VULN_SCRIPTS[code]
    cmd = script['fix_cmd']
    inputs = req.params
    if "inputs" in script:
        for inp in script["inputs"]:
            if inp["key"] not in inputs: inputs[inp["key"]] = inp.get("default", "")
    for k, v in inputs.items(): cmd = cmd.replace("{"+k+"}", str(v))
    status, out = ssh.run_command(cmd)
    ssh.close()
    res = "✅ 조치 성공" if status == 0 else f"ℹ️ 결과/가이드:\n{out}"
    is_vuln = (status != 0)
    db.save_scan_result(ip, code, res, is_vuln)
    return {"result": res}

# --- AI API ---
@app.post("/ai/analyze")
async def analyze_vuln_ai(request: Request, code: str = Form(...), output: str = Form(...)):
    if not await get_current_user(request): return {"success": False, "msg": "Login Required"}
    script_info = VULN_SCRIPTS.get(code, {})
    name = script_info.get("name", code)
    desc = script_info.get("description", "")
    # AI 모듈 호출
    ai_response = ai_manager.ask_ai(name, desc, output)
    return {"success": True, "analysis": ai_response}

# --- FIM API ---
@app.post("/fim/add")
async def add_fim(request: Request, ip: str=Form(...), path: str=Form(...)):
    if not await get_current_user(request): return {"success": False}
    auth = db.get_server_auth(ip)
    ssh = SSHManager(ip, auth['username'], auth['password'])
    status, out = ssh.run_command(f"sha256sum {path}")
    ssh.close()
    if status!=0: return {"success": False, "msg": "파일 없음"}
    db.add_fim_target(ip, path, out.split()[0])
    return {"success": True, "msg": "✅ 등록 완료"}

@app.post("/fim/check/{ip}")
async def check_fim(request: Request, ip: str):
    if not await get_current_user(request): return {"success": False}
    auth = db.get_server_auth(ip)
    ssh = SSHManager(ip, auth['username'], auth['password'])
    if not ssh.connect(): return {"success": False}
    targets = db.get_fim_list(ip)
    for t in targets:
        status, out = ssh.run_command(f"sha256sum {t['file_path']}")
        new_st = "MISSING" if status!=0 else ("OK" if out.split()[0]==t['baseline_hash'] else "CHANGED")
        db.update_fim_status(ip, t['file_path'], out.split()[0] if status==0 else "", new_st)
    ssh.close()
    return {"success": True, "msg": "검사 완료"}

@app.post("/fim/delete")
async def del_fim(request: Request, id: int=Form(...)):
    if not await get_current_user(request): return {"success": False}
    db.delete_fim_target(id)
    return {"success": True}

@app.post("/fim/acknowledge")
async def ack_fim(request: Request, id: int=Form(...)):
    if not await get_current_user(request): return {"success": False}
    db.acknowledge_fim_change(id)
    return {"success": True, "msg": "✅ 변경 승인 완료"}

# [main.py] 하단 API 영역에 추가

@app.post("/ai/inspect_file")
async def inspect_file_ai(request: Request, ip: str = Form(...), path: str = Form(...)):
    if not await get_current_user(request): return {"success": False, "msg": "로그인 필요"}
    
    # 1. DB에서 접속 정보 확인
    auth = db.get_server_auth(ip)
    ssh = SSHManager(ip, auth['username'], auth['password'])
    
    # 2. 파일 내용 읽어오기 (cat 명령어)
    # 보안상 텍스트 파일인지 확인하는 로직이 있으면 좋지만 여기선 바로 읽음
    status, content = ssh.run_command(f"cat {path}")
    ssh.close()
    
    if status != 0:
        return {"success": False, "msg": f"파일을 읽을 수 없습니다.\n{content}"}
    
    # 3. AI에게 코드 분석 요청
    ai_result = ai_manager.analyze_code(path, content)
    
    return {"success": True, "analysis": ai_result, "code_preview": content[:500]} # 미리보기 일부 반환
