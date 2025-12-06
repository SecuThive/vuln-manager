# scripts_db.py
# 주요정보통신기반시설 기술적 취약점 가이드 (Linux) U-01 ~ U-72 + U-99 (Webshell)
#
# [Logic Guide]
# - inputs: 사용자에게 입력받을 필드 정의 (type: number, text, select, textarea)
# - check_cmd: (현재설정출력) && (검증로직 && exit 1 || exit 0)
#   -> Exit 1: 양호 (Safe)
#   -> Exit 0: 취약 (Vulnerable)
# - fix_cmd:
#   -> 자동 조치: sed/chmod 등으로 설정 변경 (성공 시 Exit 0)
#   -> 수동 조치: echo로 가이드 출력 (Exit 1 반환하여 취약 상태 유지)

VULN_SCRIPTS = {
    # ==============================================================================
    # 1. 계정 관리 (Account Management)
    # ==============================================================================
    "U-01": {
        "name": "Root 계정 원격 접속 제한",
        "description": "SSH 설정(PermitRootLogin)을 점검하여 Root 직접 접속을 제한합니다.",
        "inputs": [{"key": "val", "label": "접속 허용 여부", "type": "select", "options": ["no", "yes"], "default": "no"}],
        "check_cmd": "(grep -E '^PermitRootLogin' /etc/ssh/sshd_config || echo '설정값: 미설정'); grep -qE '^PermitRootLogin[[:space:]]+no' /etc/ssh/sshd_config && exit 1 || exit 0",
        "fix_cmd": "sed -i 's/^.*PermitRootLogin.*/PermitRootLogin {val}/g' /etc/ssh/sshd_config && systemctl reload sshd"
    },
    "U-02": {
        "name": "패스워드 복잡성 설정",
        "description": "pwquality.conf를 수정하여 패스워드 길이 및 문자 조합을 강제합니다.",
        "inputs": [
            {"key": "minlen", "label": "최소 길이", "type": "number", "default": "9"},
            {"key": "lcredit", "label": "소문자 최소개수 (-1:필수)", "type": "number", "default": "-1"},
            {"key": "ucredit", "label": "대문자 최소개수", "type": "number", "default": "-1"},
            {"key": "dcredit", "label": "숫자 최소개수", "type": "number", "default": "-1"},
            {"key": "ocredit", "label": "특수문자 최소개수", "type": "number", "default": "-1"}
        ],
        "check_cmd": "grep -E '^(minlen|lcredit|ucredit|dcredit|ocredit)' /etc/security/pwquality.conf || echo '일부 미설정'",
        "fix_cmd": (
            "sed -i 's/^.*minlen.*/minlen = {minlen}/' /etc/security/pwquality.conf && "
            "sed -i 's/^.*lcredit.*/lcredit = {lcredit}/' /etc/security/pwquality.conf && "
            "sed -i 's/^.*ucredit.*/ucredit = {ucredit}/' /etc/security/pwquality.conf && "
            "sed -i 's/^.*dcredit.*/dcredit = {dcredit}/' /etc/security/pwquality.conf && "
            "sed -i 's/^.*ocredit.*/ocredit = {ocredit}/' /etc/security/pwquality.conf"
        )
    },
    "U-03": {
        "name": "계정 잠금 임계값 설정",
        "description": "로그인 실패 시 계정 잠금 정책(faillock)을 설정합니다.",
        "inputs": [
            {"key": "deny", "label": "잠금 허용 횟수", "type": "number", "default": "5"},
            {"key": "unlock_time", "label": "잠금 시간(초)", "type": "number", "default": "600"}
        ],
        "check_cmd": "grep -E '^(deny|unlock_time)' /etc/security/faillock.conf || echo '설정값: 미설정'",
        "fix_cmd": "authselect enable-feature with-faillock && sed -i 's/^.*deny.*/deny = {deny}/' /etc/security/faillock.conf && sed -i 's/^.*unlock_time.*/unlock_time = {unlock_time}/' /etc/security/faillock.conf"
    },
    "U-04": {
        "name": "패스워드 파일 보호",
        "description": "/etc/shadow 파일이 존재하는지 확인합니다.",
        "inputs": [],
        "check_cmd": "[ -f /etc/shadow ] && exit 1 || echo 'shadow 파일 없음' && exit 0",
        "fix_cmd": "pwconv"
    },
    "U-44": {
        "name": "UID 0인 일반 계정 (수동)",
        "description": "Root 이외에 UID가 0인 계정이 있는지 탐지합니다.",
        "inputs": [],
        "check_cmd": "(awk -F: '$3 == 0 && $1 != \"root\" {print $1}' /etc/passwd | grep . || echo '안전함'); awk -F: '$3 == 0 && $1 != \"root\" {print $1}' /etc/passwd | grep -q . && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\nUID 0인 계정은 시스템에 치명적일 수 있습니다.\n터미널에서 확인 후 삭제하세요:\n# awk -F: \"$3 == 0\" /etc/passwd\n# userdel [계정명]' && exit 1"
    },
    "U-45": {
        "name": "Root 계정 su 제한 (수동)",
        "description": "su 명령어를 특정 그룹(wheel)만 사용할 수 있게 제한합니다.",
        "inputs": [],
        "check_cmd": "grep 'pam_wheel.so' /etc/pam.d/su >/dev/null && exit 1 || echo 'pam_wheel.so 미설정' && exit 0",
        "fix_cmd": "echo '[수동 조치 가이드]\n/etc/pam.d/su 파일에서 다음 줄의 주석을 해제하세요:\nauth required pam_wheel.so use_uid' && exit 1"
    },
    "U-46": {
        "name": "패스워드 최소 길이 (Login.defs)",
        "description": "PASS_MIN_LEN 값을 설정합니다.",
        "inputs": [{"key": "len", "label": "최소 길이", "type": "number", "default": "8"}],
        "check_cmd": "grep '^PASS_MIN_LEN' /etc/login.defs || echo '미설정'; grep -E '^PASS_MIN_LEN[[:space:]]+([8-9]|[0-9]{2})' /etc/login.defs >/dev/null && exit 1 || exit 0",
        "fix_cmd": "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    {len}/' /etc/login.defs"
    },
    "U-47": {
        "name": "패스워드 최대 사용 기간",
        "description": "PASS_MAX_DAYS 값을 설정합니다.",
        "inputs": [{"key": "days", "label": "최대 기간(일)", "type": "number", "default": "90"}],
        "check_cmd": "grep '^PASS_MAX_DAYS' /etc/login.defs || echo '미설정'; grep -E '^PASS_MAX_DAYS[[:space:]]+([0-9]|[1-8][0-9]|90)$' /etc/login.defs >/dev/null && exit 1 || exit 0",
        "fix_cmd": "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   {days}/' /etc/login.defs"
    },
    "U-48": {
        "name": "패스워드 최소 사용 기간",
        "description": "PASS_MIN_DAYS 값을 설정합니다.",
        "inputs": [{"key": "days", "label": "최소 기간(일)", "type": "number", "default": "1"}],
        "check_cmd": "grep '^PASS_MIN_DAYS' /etc/login.defs || echo '미설정'; grep -E '^PASS_MIN_DAYS[[:space:]]+[1-9]' /etc/login.defs >/dev/null && exit 1 || exit 0",
        "fix_cmd": "sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   {days}/' /etc/login.defs"
    },
    "U-49": {
        "name": "불필요한 계정 제거 (수동)",
        "description": "lp, uucp 등 사용하지 않는 시스템 계정을 점검합니다.",
        "inputs": [],
        "check_cmd": "egrep '^(lp|uucp|games|gopher):' /etc/passwd >/dev/null && echo '불필요 계정 존재' && exit 0 || (echo '안전함'; exit 1)",
        "fix_cmd": "echo '[수동 조치 가이드]\n불필요한 계정을 삭제하세요.\n# userdel lp\n# userdel uucp' && exit 1"
    },
    "U-50": {
        "name": "관리자 그룹(Wheel) 점검 (수동)",
        "description": "Wheel 그룹에 불필요한 계정이 있는지 확인합니다.",
        "inputs": [],
        "check_cmd": "grep '^wheel' /etc/group || echo 'Wheel 그룹 없음'; exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\n/etc/group 파일을 확인하여 wheel 그룹 멤버를 관리하세요.' && exit 1"
    },
    "U-52": {
        "name": "중복 UID 점검 (수동)",
        "description": "동일한 UID를 사용하는 계정이 있는지 점검합니다.",
        "inputs": [],
        "check_cmd": "awk -F: '{print $3}' /etc/passwd | sort | uniq -d | grep . && echo '중복 UID 발견' && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\n중복 UID를 가진 계정의 UID를 변경하세요.\n# usermod -u [NEW_UID] [계정명]' && exit 1"
    },
    "U-53": {
        "name": "사용자 쉘 점검 (수동)",
        "description": "로그인이 불필요한 계정에 쉘이 부여되어 있는지 확인합니다.",
        "inputs": [],
        "check_cmd": "awk -F: '$3 > 1000 && $7 !~ /nologin|false/ {print $1, $7}' /etc/passwd | grep . && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\n일반 계정의 쉘을 /sbin/nologin으로 변경하세요.\n# usermod -s /sbin/nologin [계정명]' && exit 1"
    },
    "U-54": {
        "name": "Session Timeout 설정",
        "description": "자동 로그아웃 시간(TMOUT)을 설정합니다.",
        "inputs": [{"key": "tmout", "label": "시간(초)", "type": "select", "options": ["300", "600", "1200", "1800"], "default": "600"}],
        "check_cmd": "grep 'TMOUT' /etc/profile || echo '미설정'; grep 'TMOUT' /etc/profile >/dev/null && exit 1 || exit 0",
        "fix_cmd": "echo 'export TMOUT={tmout}' >> /etc/profile && source /etc/profile"
    },

    # ==============================================================================
    # 2. 파일 및 디렉터리 관리 (File Management)
    # ==============================================================================
    "U-05": {
        "name": "PATH 환경변수 점검 (수동)",
        "description": "PATH 변수에 현재 디렉터리(.)가 포함되어 있는지 확인합니다.",
        "inputs": [],
        "check_cmd": "echo $PATH | grep -E '(^|:)(\.|:|$)' >/dev/null && echo 'PATH에 . 포함됨' && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\n/etc/profile 또는 ~/.bash_profile 파일에서\nPATH 변수에 포함된 \".\"을 제거하십시오.' && exit 1"
    },
    "U-06": {
        "name": "소유자 없는 파일 점검 (수동)",
        "description": "시스템에 소유자(nouser)가 없는 파일을 검색합니다.",
        "inputs": [],
        "check_cmd": "find /home -nouser 2>/dev/null | head -n 5 | grep . && echo '...외 다수 발견' && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\n소유자가 없는 파일은 삭제하거나 소유자를 지정하세요.\n# find / -nouser' && exit 1"
    },
    "U-07": {
        "name": "/etc/passwd 파일 권한",
        "description": "파일의 권한을 설정합니다.",
        "inputs": [{"key": "perm", "label": "권한 (644 권장)", "type": "text", "default": "644"}],
        "check_cmd": "stat -c '%a %U' /etc/passwd; stat -c '%a' /etc/passwd | grep -q '644' && exit 1 || exit 0",
        "fix_cmd": "chmod {perm} /etc/passwd && chown root:root /etc/passwd"
    },
    "U-08": {
        "name": "/etc/shadow 파일 권한",
        "description": "파일의 권한을 설정합니다.",
        "inputs": [{"key": "perm", "label": "권한 (400 권장)", "type": "text", "default": "400"}],
        "check_cmd": "stat -c '%a %U' /etc/shadow; stat -c '%a' /etc/shadow | grep -q '400' && exit 1 || exit 0",
        "fix_cmd": "chmod {perm} /etc/shadow && chown root:root /etc/shadow"
    },
    "U-09": {
        "name": "/etc/hosts 파일 권한",
        "description": "파일의 권한을 설정합니다.",
        "inputs": [{"key": "perm", "label": "권한 (600 권장)", "type": "text", "default": "600"}],
        "check_cmd": "stat -c '%a' /etc/hosts | grep -q '600' && exit 1 || exit 0",
        "fix_cmd": "chmod {perm} /etc/hosts && chown root:root /etc/hosts"
    },
    "U-11": {
        "name": "/etc/rsyslog.conf 파일 권한",
        "description": "파일의 권한을 설정합니다.",
        "inputs": [{"key": "perm", "label": "권한 (640 권장)", "type": "text", "default": "640"}],
        "check_cmd": "stat -c '%a' /etc/rsyslog.conf | grep -q '640' && exit 1 || exit 0",
        "fix_cmd": "chmod {perm} /etc/rsyslog.conf && chown root:root /etc/rsyslog.conf"
    },
    "U-12": {
        "name": "/etc/services 파일 권한",
        "description": "파일의 권한을 설정합니다.",
        "inputs": [{"key": "perm", "label": "권한 (644 권장)", "type": "text", "default": "644"}],
        "check_cmd": "stat -c '%a' /etc/services | grep -q '644' && exit 1 || exit 0",
        "fix_cmd": "chmod {perm} /etc/services && chown root:root /etc/services"
    },
    "U-13": {
        "name": "SUID/SGID 설정 파일 점검",
        "description": "주요 실행 파일(chfn, chsh, wall)의 SUID를 제거합니다.",
        "inputs": [],
        "check_cmd": "find /usr/bin/chfn /usr/bin/chsh /usr/bin/wall -perm -4000 2>/dev/null | grep . && exit 0 || exit 1",
        "fix_cmd": "chmod -s /usr/bin/chfn /usr/bin/chsh /usr/bin/wall"
    },
    "U-14": {
        "name": "시작파일 권한 점검 (수동)",
        "description": "환경설정 파일(.bashrc 등) 권한 점검",
        "inputs": [],
        "check_cmd": "find /root /home -name '.bashrc' -perm -002 2>/dev/null | grep . && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\n환경 설정 파일에 쓰기 권한이 있습니다. 644로 변경하세요.' && exit 1"
    },
    "U-15": {
        "name": "World Writable 파일 점검 (수동)",
        "description": "누구나 쓸 수 있는 파일을 검색합니다.",
        "inputs": [],
        "check_cmd": "find /etc -perm -2 -type f 2>/dev/null | head -n 5 | grep . && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\n보안상 위험한 파일입니다. 권한을 644 등으로 변경하세요.\n# find /etc -perm -2 -type f -exec chmod o-w {} \;' && exit 1"
    },
    "U-17": {
        "name": ".rhosts, hosts.equiv 점검",
        "description": "r-command 인증 파일을 삭제합니다.",
        "inputs": [],
        "check_cmd": "ls /etc/hosts.equiv 2>/dev/null && exit 0 || exit 1",
        "fix_cmd": "rm -f /etc/hosts.equiv"
    },
    "U-18": {
        "name": "접속 IP 및 포트 제한",
        "description": "hosts.deny에 ALL:ALL 설정을 추가합니다.",
        "inputs": [],
        "check_cmd": "grep 'ALL:ALL' /etc/hosts.deny >/dev/null && exit 1 || exit 0",
        "fix_cmd": "echo 'ALL:ALL' >> /etc/hosts.deny"
    },
    "U-56": {
        "name": "UMASK 설정 관리",
        "description": "기본 umask를 022로 설정합니다.",
        "inputs": [],
        "check_cmd": "grep -i 'umask 022' /etc/profile >/dev/null && exit 1 || exit 0",
        "fix_cmd": "echo 'umask 022' >> /etc/profile && source /etc/profile"
    },

    # ==============================================================================
    # 3. 서비스 관리 (Service Management)
    # ==============================================================================
    "U-19": {
        "name": "Finger 서비스 비활성화",
        "description": "Finger 서비스를 중지하고 비활성화합니다.",
        "inputs": [],
        "check_cmd": "systemctl is-active finger >/dev/null && exit 0 || exit 1",
        "fix_cmd": "systemctl stop finger && systemctl disable finger"
    },
    "U-20": {
        "name": "Anonymous FTP 비활성화",
        "description": "vsftpd 설정에서 익명 접속을 차단합니다.",
        "inputs": [],
        "check_cmd": "grep -qE '^anonymous_enable=NO' /etc/vsftpd/vsftpd.conf 2>/dev/null && exit 1 || exit 0",
        "fix_cmd": "sed -i 's/^.*anonymous_enable.*/anonymous_enable=NO/g' /etc/vsftpd/vsftpd.conf && systemctl try-restart vsftpd"
    },
    "U-21": {
        "name": "r 계열 서비스 비활성화",
        "description": "rlogin, rsh, rexec 서비스를 차단합니다.",
        "inputs": [],
        "check_cmd": "systemctl is-active rlogin rsh rexec >/dev/null && exit 0 || exit 1",
        "fix_cmd": "systemctl stop rlogin rsh rexec; systemctl disable rlogin rsh rexec"
    },
    "U-22": {
        "name": "Cron 파일 권한 설정",
        "description": "/etc/crontab 권한을 644로 설정합니다.",
        "inputs": [],
        "check_cmd": "stat -c '%a' /etc/crontab | grep -q '644' && exit 1 || exit 0",
        "fix_cmd": "chmod 644 /etc/crontab && chown root:root /etc/crontab"
    },
    "U-23": {
        "name": "DoS 취약 서비스 비활성화",
        "description": "echo, discard, daytime, chargen 서비스를 차단합니다.",
        "inputs": [],
        "check_cmd": "systemctl is-active echo discard daytime chargen >/dev/null && exit 0 || exit 1",
        "fix_cmd": "systemctl stop echo discard daytime chargen; systemctl disable echo discard daytime chargen"
    },
    "U-24": {
        "name": "NFS 서비스 비활성화 (선택)",
        "description": "사용하지 않는 NFS 서비스를 중지합니다.",
        "inputs": [],
        "check_cmd": "systemctl is-active nfs-server >/dev/null && exit 0 || exit 1",
        "fix_cmd": "systemctl stop nfs-server && systemctl disable nfs-server"
    },
    "U-25": {
        "name": "NFS 접근통제 (수동)",
        "description": "/etc/exports 설정 파일 내용을 확인합니다.",
        "inputs": [],
        "check_cmd": "[ -s /etc/exports ] && cat /etc/exports && exit 0 || (echo '파일 비어있음(안전)'; exit 1)",
        "fix_cmd": "echo '[수동 조치 가이드]\n/etc/exports 파일에 공유 설정이 있습니다.\n불필요한 공유는 삭제하고, 필요한 경우 접근 IP를 제한하세요.' && exit 1"
    },
    "U-27": {
        "name": "RPC 서비스 확인",
        "description": "불필요한 RPC 서비스를 비활성화합니다.",
        "inputs": [],
        "check_cmd": "systemctl is-active rstatd rusersd walld >/dev/null && exit 0 || exit 1",
        "fix_cmd": "systemctl stop rstatd rusersd walld; systemctl disable rstatd rusersd walld"
    },
    "U-28": {
        "name": "NIS, NIS+ 점검",
        "description": "NIS 서비스 비활성화",
        "inputs": [],
        "check_cmd": "systemctl is-active ypserv ypbind >/dev/null && exit 0 || exit 1",
        "fix_cmd": "systemctl stop ypserv ypbind; systemctl disable ypserv ypbind"
    },
    "U-29": {
        "name": "tftp, talk 서비스 비활성화",
        "description": "tftp, talk 서비스 중지",
        "inputs": [],
        "check_cmd": "systemctl is-active tftp talk ntalk >/dev/null && exit 0 || exit 1",
        "fix_cmd": "systemctl stop tftp talk ntalk; systemctl disable tftp talk ntalk"
    },
    "U-30": {
        "name": "Sendmail 버전 점검 (수동)",
        "description": "Sendmail 버전을 확인합니다.",
        "inputs": [],
        "check_cmd": "command -v sendmail >/dev/null && sendmail -d0.1 -bt < /dev/null | head -1 && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\nSendmail을 최신 버전으로 업데이트하거나 사용하지 않으면 삭제하세요.' && exit 1"
    },
    "U-31": {
        "name": "스팸 메일 릴레이 제한 (수동)",
        "description": "SMTP 릴레이 제한 설정",
        "inputs": [],
        "check_cmd": "grep 'smtpd_relay_restrictions' /etc/postfix/main.cf >/dev/null && exit 1 || exit 0",
        "fix_cmd": "echo '[수동 조치 가이드]\npostfix 설정에서 smtpd_relay_restrictions 옵션을 설정하세요.' && exit 1"
    },
    "U-33": {
        "name": "DNS 보안 버전 패치 (수동)",
        "description": "BIND 버전 확인",
        "inputs": [],
        "check_cmd": "named -v >/dev/null 2>&1 && named -v && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\nBIND DNS를 최신 버전으로 업데이트하세요.' && exit 1"
    },
    "U-34": {
        "name": "DNS Zone Transfer 설정 (수동)",
        "description": "Zone Transfer 제한 확인",
        "inputs": [],
        "check_cmd": "grep 'allow-transfer' /etc/named.conf >/dev/null && exit 1 || exit 0",
        "fix_cmd": "echo '[수동 조치 가이드]\n/etc/named.conf에 allow-transfer { none; }; 를 추가하세요.' && exit 1"
    },
    "U-60": {
        "name": "SSH 원격 접속 설정",
        "description": "SSH Protocol 2 사용을 강제합니다.",
        "inputs": [],
        "check_cmd": "(grep '^Protocol' /etc/ssh/sshd_config || echo '미설정'); grep -q 'Protocol 2' /etc/ssh/sshd_config && exit 1 || exit 0",
        "fix_cmd": "echo 'Protocol 2' >> /etc/ssh/sshd_config && systemctl reload sshd"
    },
    "U-61": {
        "name": "FTP 서비스 확인 (수동)",
        "description": "불필요한 FTP 서비스 확인",
        "inputs": [],
        "check_cmd": "systemctl is-active vsftpd proftpd >/dev/null && exit 0 || exit 1",
        "fix_cmd": "echo '[수동 조치 가이드]\nFTP 서비스가 필요 없다면 중지하세요.\n# systemctl stop vsftpd' && exit 1"
    },
    "U-64": {
        "name": "ftpusers 파일 설정",
        "description": "root 계정의 FTP 접속을 제한합니다.",
        "inputs": [],
        "check_cmd": "grep '^root' /etc/vsftpd/ftpusers >/dev/null && exit 1 || exit 0",
        "fix_cmd": "echo 'root' >> /etc/vsftpd/ftpusers"
    },
    "U-66": {
        "name": "SNMP 서비스 점검",
        "description": "SNMP 서비스를 비활성화합니다.",
        "inputs": [],
        "check_cmd": "systemctl is-active snmpd >/dev/null && exit 0 || exit 1",
        "fix_cmd": "systemctl stop snmpd && systemctl disable snmpd"
    },
    "U-68": {
        "name": "로그온 배너 설정",
        "description": "로그인 경고 메시지(Banner)를 설정합니다.",
        "inputs": [
            {"key": "banner", "label": "배너 내용 입력", "type": "textarea", "default": "Authorized uses only. All activity may be monitored."}
        ],
        "check_cmd": "[ -s /etc/motd ] && cat /etc/motd && exit 1 || (echo '배너 없음'; exit 0)",
        "fix_cmd": "echo '{banner}' > /etc/motd"
    },
    "U-69": {
        "name": "NFS 설정파일 접근 제한",
        "description": "/etc/exports 파일 권한을 644로 설정합니다.",
        "inputs": [],
        "check_cmd": "stat -c '%a' /etc/exports 2>/dev/null | grep -q '644' && exit 1 || exit 0",
        "fix_cmd": "chmod 644 /etc/exports && chown root:root /etc/exports"
    },
    "U-70": {
        "name": "SMTP EXPN/VRFY 제한 (수동)",
        "description": "Postfix 설정 확인",
        "inputs": [],
        "check_cmd": "grep 'disable_vrfy_command' /etc/postfix/main.cf >/dev/null && exit 1 || exit 0",
        "fix_cmd": "echo '[수동 가이드]\npostfix 설정에 disable_vrfy_command = yes 를 추가하세요.' && exit 1"
    },
    "U-72": {
        "name": "정책에 따른 시스템 로깅 설정 (수동)",
        "description": "rsyslog 등 로그 정책 확인",
        "inputs": [],
        "check_cmd": "systemctl is-active rsyslog >/dev/null && exit 1 || exit 0",
        "fix_cmd": "echo '[수동 가이드]\nrsyslog 서비스를 활성화하고 /etc/rsyslog.conf 정책을 검토하세요.' && exit 1"
    },

    # ==============================================================================
    # 5. 웹쉘 및 악성코드 탐지 (U-99) - 경로 에러 방지 버전
# ==============================================================================
    # 5. 웹쉘 및 악성코드 탐지 (U-99) - 루트 스캔 최적화 버전
    # ==============================================================================
    "U-99": {
        "name": "전체 시스템 웹쉘/악성코드 탐지",
        "description": "서버 전체(/)에서 위험한 패턴을 검색합니다. (시스템 폴더 제외)",
        "inputs": [
            # 기본값을 '/'로 설정
            {"key": "path", "label": "점검 시작 경로 (기본: /)", "type": "text", "default": "/"},
            # 확장자 필터
            {"key": "ext", "label": "확장자 (php|jsp|sh|pl|py)", "type": "text", "default": "php|jsp|asp|aspx|sh|py|pl"}
        ],
        # [수정된 로직 - 임시 파일 사용 방식]
        # 1. /tmp/scan_result.txt 파일을 비움
        # 2. find 명령어로 시스템 폴더(-prune)는 건너뛰고 파일만 찾음
        # 3. grep으로 패턴 검색 후 결과를 임시 파일에 저장 (에러는 /dev/null로 버림)
        # 4. 임시 파일 크기가 0보다 크면(-s) 취약(Exit 0), 아니면 양호(Exit 1)
        "check_cmd": """
            RESULT_FILE="/tmp/web_scan_result.txt"
            > "$RESULT_FILE"
            
            find {path} -type d \\( -path "/proc" -o -path "/sys" -o -path "/dev" -o -path "/run" -o -path "/boot" -o -path "/snap" -o -path "/var/lib/docker" -o -path "/overlay" \\) -prune -o -type f 2>/dev/null | grep -E "\.({ext})$" | xargs -r grep -lE "eval\(|system\(|shell_exec\(|passthru\(|base64_decode\(|popen\(|proc_open\(|cmd\.exe|/bin/sh" 2>/dev/null >> "$RESULT_FILE"
            
            if [ -s "$RESULT_FILE" ]; then
                echo "⚠️ 의심 파일 발견 (상위 20개):"
                head -n 20 "$RESULT_FILE"
                rm -f "$RESULT_FILE"
                exit 0
            else
                echo "✅ 안전 (의심 파일 없음)"
                rm -f "$RESULT_FILE"
                exit 1
            fi
        """,
        "fix_cmd": "echo '[수동 가이드]\n발견된 파일을 확인 후 악성 코드라면 삭제하세요.\n# rm -f [파일경로]' && exit 1"
    }
}
