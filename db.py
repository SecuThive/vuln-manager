import os
from dotenv import load_dotenv
import pymysql

load_dotenv() # .env 파일 로드

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "127.0.0.1"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD"), # 여기서 환경변수를 가져옴
    "db": os.getenv("DB_NAME", "vuln_manager"),
    "charset": "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor
}

def get_conn(): return pymysql.connect(**DB_CONFIG)

# --- User ---
def get_user(username):
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
            return cursor.fetchone()
    finally: conn.close()

# --- Server ---
def add_server(ip, user, password):
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            sql = "INSERT INTO servers (ip, username, password) VALUES (%s, %s, %s) ON DUPLICATE KEY UPDATE username=%s, password=%s"
            cursor.execute(sql, (ip, user, password, user, password))
        conn.commit()
    finally: conn.close()

def get_servers():
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM servers")
            servers = cursor.fetchall()
            cursor.execute("SELECT * FROM scan_results")
            results = cursor.fetchall()
            
            res_map = {}
            for r in results:
                if r['server_ip'] not in res_map: res_map[r['server_ip']] = {}
                res_map[r['server_ip']][r['vuln_code']] = {"status": r['status'], "vulnerable": bool(r['is_vulnerable']), "last_check": str(r['last_check'])}
            
            final = {}
            for s in servers:
                s['results'] = res_map.get(s['ip'], {})
                final[s['ip']] = s
            return final
    finally: conn.close()

def get_server_auth(ip):
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username, password FROM servers WHERE ip=%s", (ip,))
            return cursor.fetchone()
    finally: conn.close()

# --- Scan Result ---
def save_scan_result(ip, code, msg, is_vuln):
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM scan_results WHERE server_ip=%s AND vuln_code=%s", (ip, code))
            cursor.execute("INSERT INTO scan_results (server_ip, vuln_code, status, is_vulnerable, last_check) VALUES (%s, %s, %s, %s, NOW())", (ip, code, msg, is_vuln))
        conn.commit()
    finally: conn.close()

# --- FIM ---
def add_fim_target(ip, path, hash_val):
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            sql = "INSERT INTO fim_targets (server_ip, file_path, baseline_hash, current_hash, last_check, status) VALUES (%s, %s, %s, %s, NOW(), 'OK') ON DUPLICATE KEY UPDATE baseline_hash=%s, current_hash=%s, status='OK', last_check=NOW()"
            cursor.execute(sql, (ip, path, hash_val, hash_val, hash_val, hash_val))
        conn.commit()
    finally: conn.close()

def get_fim_list(ip):
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM fim_targets WHERE server_ip=%s", (ip,))
            return cursor.fetchall()
    finally: conn.close()

def update_fim_status(ip, path, cur_hash, status):
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE fim_targets SET current_hash=%s, status=%s, last_check=NOW() WHERE server_ip=%s AND file_path=%s", (cur_hash, status, ip, path))
        conn.commit()
    finally: conn.close()

def delete_fim_target(id):
    conn = get_conn()
    try:
        with conn.cursor() as cursor: cursor.execute("DELETE FROM fim_targets WHERE id=%s", (id,))
        conn.commit()
    finally: conn.close()

def acknowledge_fim_change(id):
    conn = get_conn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE fim_targets SET baseline_hash = current_hash, status = 'OK', last_check = NOW() WHERE id = %s", (id,))
        conn.commit()
    finally: conn.close()
