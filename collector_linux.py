import subprocess
import socket
import json
import requests
import time
import os
import platform
from datetime import datetime, timezone
import re
import os

# Default server URL (can be overridden by env var or --server)
SERVER_URL = os.environ.get("SERVER_URL", "http://192.168.3.24:8000/api/collect")
API_KEY = os.environ.get("API_KEY")
import argparse

def normalize_name(s: str) -> str:
    if not s:
        return s or ""
    s = s.strip()
    s = re.sub(r"[\x00-\x1f\x7f]+", "", s)
    ascii_count = sum(1 for ch in s if ord(ch) < 128)
    if ascii_count / max(1, len(s)) > 0.9:
        return s
    candidates = [s]
    for enc in ("latin1", "cp1252", "cp1251"):
        try:
            b = s.encode(enc)
        except Exception:
            continue
        for dec in ("cp1251", "utf-8", "cp866"):
            try:
                cand = b.decode(dec)
                candidates.append(cand)
            except Exception:
                pass

    def score(text: str) -> int:
        if not text:
            return -1000
        score = 0
        for ch in text:
            if ch.isalpha() or ch.isdigit():
                score += 2
            elif ch.isspace() or ch in "._-:(),[]":
                score += 1
            elif ord(ch) >= 0x0400 and ord(ch) <= 0x04FF:
                score += 3
            elif ch == '\ufffd':
                score -= 10
            else:
                score -= 1
        return score

    best = max(candidates, key=score)
    return best


def get_hostname():
    return socket.gethostname()


def get_ip():
    try:
        # Попытка получить внешний IP интерфейса
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def get_os():
    return platform.system() + " " + platform.release()


def parse_dpkg():
    apps = []
    try:
        res = subprocess.run(["dpkg", "-l"], capture_output=True, text=True, check=True)
        lines = res.stdout.splitlines()
        for line in lines[5:]:
            parts = line.split()
            if len(parts) >= 3 and parts[0] == 'ii':
                apps.append({"name": normalize_name(parts[1]), "version": parts[2]})
    except Exception:
        pass
    return apps


def parse_rpm():
    apps = []
    try:
        res = subprocess.run(["rpm", "-qa", "--qf", "%{NAME} %{VERSION}\n"], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                apps.append({"name": normalize_name(parts[0]), "version": parts[1]})
    except Exception:
        pass
    return apps


def parse_pip():
    apps = []
    try:
        res = subprocess.run(["pip", "list", "--format=freeze"], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            if "==" in line:
                name, ver = line.split("==", 1)
                apps.append({"name": normalize_name(name), "version": ver})
    except Exception:
        pass
    return apps


def parse_npm():
    apps = []
    try:
        res = subprocess.run(["npm", "-g", "list", "--depth=0", "--parseable"], capture_output=True, text=True, check=True)
        for line in res.stdout.splitlines():
            if "/node_modules/" in line:
                base = os.path.basename(line)
                apps.append({"name": normalize_name(base), "version": ""})
    except Exception:
        pass
    return apps


def get_installed_software():
    software_list = []

    if os.path.exists("/usr/bin/dpkg"):
        software_list.extend(parse_dpkg())
    if os.path.exists("/usr/bin/rpm"):
        software_list.extend(parse_rpm())

    # Дополнительные источники
    software_list.extend(parse_pip())
    software_list.extend(parse_npm())

    # Убрать дубликаты по (name, version)
    seen = set()
    out = []
    for it in software_list:
        key = (it.get('name'), it.get('version'))
        if key not in seen:
            seen.add(key)
            out.append(it)
    return out


def save_report_local(data, out_dir=None):
    if out_dir is None:
        out_dir = os.path.join(os.path.dirname(__file__), "reports")
    os.makedirs(out_dir, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    host = data.get("hostname") or get_hostname()
    safe_host = ''.join(c for c in host if c.isalnum() or c in ('-', '_')).rstrip()
    filename = f"report_{safe_host}_{ts}.json"
    path = os.path.join(out_dir, filename)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[+] Отчёт сохранён локально: {path}")
    return path


def send_report_if_configured(data):
    server = SERVER_URL
    headers = {'Content-Type': 'application/json'}
    if API_KEY:
        headers['X-API-KEY'] = API_KEY
    tries = 3
    for attempt in range(1, tries + 1):
        try:
            resp = requests.post(server, json=data, timeout=5, headers=headers)
            if resp.status_code == 200:
                print('[+] Отчёт отправлен на сервер')
                return True
            else:
                print(f'[!] Сервер вернул {resp.status_code}: {resp.text}')
        except Exception as e:
            print(f'[!] Ошибка отправки (attempt {attempt}): {e}')
        time.sleep(attempt)
    return False


def main(out_dir=None):
    parser = argparse.ArgumentParser(description="Linux collector")
    parser.add_argument("--server", help="Server URL to POST reports to")
    parser.add_argument("--key", help="API key for authentication")
    args = parser.parse_args()
    global SERVER_URL, API_KEY
    if args.server:
        SERVER_URL = args.server
    if args.key:
        API_KEY = args.key
    print(f"[i] Using SERVER_URL = {SERVER_URL}")
    if API_KEY:
        print(f"[i] Using API_KEY for authentication")

    data = {
        "collected_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "hostname": get_hostname(),
        "ip": get_ip(),
        "os": get_os(),
        "software": get_installed_software()
    }

    sent = send_report_if_configured(data)
    if not sent:
        save_report_local(data, out_dir=out_dir)


if __name__ == "__main__":
    main()
