#!/usr/bin/env python3
import subprocess
import socket
import json
import os
import platform
from datetime import datetime, timezone
import re
import requests
import time

# Жёстко прописанный адрес сервера для отправки отчётов
SERVER_URL = "http://192.168.3.15:8000/api/collect"


def normalize_name(s: str) -> str:
    if not s:
        return s or ""
    s = s.strip()
    # remove control characters
    s = re.sub(r"[\x00-\x1f\x7f]+", "", s)

    # If mostly ASCII, return as-is
    ascii_count = sum(1 for ch in s if ord(ch) < 128)
    if ascii_count / max(1, len(s)) > 0.9:
        return s

    candidates = [s]
    # Try common mojibake fixes: re-encode as latin1/cp1252 then decode as cp1251/utf-8/cp866
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

    # Choose best candidate by readability score
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
                # cyrillic
                score += 3
            elif ch == '\ufffd':
                score -= 10
            else:
                score -= 1
        return score

    best = max(candidates, key=score)
    return best

try:
    import winreg
except Exception:
    winreg = None


def get_hostname():
    return socket.gethostname()


def get_ip():
    try:
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


def parse_registry_uninstall():
    apps = []
    if winreg is None:
        return apps

    roots = [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]
    subpaths = [r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                r"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"]
    for root in roots:
        for sub in subpaths:
            try:
                key = winreg.OpenKey(root, sub)
            except Exception:
                continue
            try:
                for i in range(0, 5000):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                    except OSError:
                        break
                    try:
                        sk = winreg.OpenKey(key, subkey_name)
                        name = None
                        version = None
                        try:
                            name = winreg.QueryValueEx(sk, 'DisplayName')[0]
                        except Exception:
                            pass
                        try:
                            version = winreg.QueryValueEx(sk, 'DisplayVersion')[0]
                        except Exception:
                            pass
                        if name:
                            apps.append({"name": normalize_name(name), "version": version or ""})
                    except Exception:
                        continue
            finally:
                try:
                    winreg.CloseKey(key)
                except Exception:
                    pass
    return apps


def parse_wmic():
    apps = []
    try:
        res = subprocess.run(["wmic", "product", "get", "name,version"], capture_output=True, text=True, check=True)
        lines = res.stdout.splitlines()
        # Пропустить пустые строки и заголовок
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Попробуем разделить последнее слово как версию
            parts = line.rsplit(None, 1)
            if len(parts) == 2:
                name, version = parts[0], parts[1]
            else:
                name, version = parts[0], ""
            apps.append({"name": normalize_name(name), "version": version})
    except Exception:
        pass
    return apps


def get_installed_software():
    software_list = []

    # Попытаться получить из реестра
    software_list.extend(parse_registry_uninstall())

    # Попытка через WMIC
    software_list.extend(parse_wmic())

    # Убрать дубликаты
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
    headers = {'Content-Type': 'application/json'}
    tries = 3
    for attempt in range(1, tries + 1):
        try:
            resp = requests.post(SERVER_URL, json=data, timeout=5, headers=headers)
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
