"""
Recommendation engine for CVE remediation.

Generates actionable remediation steps for each CVE based on:
  - CVSS score / severity
  - CVE description keyword analysis
  - EPSS score and KEV membership
  - Affected package name patterns

Each recommendation references Russian regulatory documents
(ФСТЭК России Приказы №17, №21, №239).
"""

from dataclasses import dataclass, field
from typing import Optional

# ── Regulatory reference catalogue ────────────────────────────────────────
# Source: ФСТЭК России
#   Приказ №17 — Требования к ГИС (государственные информационные системы)
#   Приказ №21 — Требования к ИСПДн (персональные данные)
#   Приказ №239 — Требования к КИИ (критическая информационная инфраструктура)

REGULATORY = {
    "АНЗ.1": {
        "code": "АНЗ.1",
        "title": "Выявление, анализ уязвимостей и оперативное устранение",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013), №239 (2017)",
        "note": "Требует выявлять уязвимости и устранять их в установленные сроки",
    },
    "АНЗ.2": {
        "code": "АНЗ.2",
        "title": "Контроль установки обновлений программного обеспечения",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013), №239 (2017)",
        "note": "Обязывает контролировать своевременность установки патчей",
    },
    "УПД.3": {
        "code": "УПД.3",
        "title": "Управление информационными потоками (фильтрация, контроль соединений)",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013)",
        "note": "Разграничение и фильтрация сетевых взаимодействий",
    },
    "УПД.13": {
        "code": "УПД.13",
        "title": "Реализация защищённых удалённых сессий доступа",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013)",
        "note": "Защита каналов передачи данных при удалённом доступе",
    },
    "ИАФ.1": {
        "code": "ИАФ.1",
        "title": "Идентификация и аутентификация пользователей",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013), №239 (2017)",
        "note": "Все пользователи должны проходить идентификацию и аутентификацию",
    },
    "ИАФ.3": {
        "code": "ИАФ.3",
        "title": "Управление идентификаторами (в т.ч. привилегированных пользователей)",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013)",
        "note": "Минимизация привилегий, контроль учётных записей с расширенными правами",
    },
    "РСБ.2": {
        "code": "РСБ.2",
        "title": "Регистрация событий безопасности",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013), №239 (2017)",
        "note": "Аудит и журналирование событий ИБ",
    },
    "ОЦЛ.1": {
        "code": "ОЦЛ.1",
        "title": "Контроль целостности программного обеспечения",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013), №239 (2017)",
        "note": "Обнаружение несанкционированных изменений ПО",
    },
    "ОПС.1": {
        "code": "ОПС.1",
        "title": "Управление установкой компонентов программного обеспечения",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013)",
        "note": "Контроль состава разрешённого к использованию ПО",
    },
    "ЗТС.3": {
        "code": "ЗТС.3",
        "title": "Управление конфигурацией объектов защиты",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013), №239 (2017)",
        "note": "Документирование и контроль конфигурации технических средств",
    },
    "ЗИС.3": {
        "code": "ЗИС.3",
        "title": "Обеспечение защиты информации от раскрытия и модификации при передаче",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013)",
        "note": "Использование криптографических протоколов при передаче данных",
    },
    "ЗСВ.1": {
        "code": "ЗСВ.1",
        "title": "Идентификация и аутентификация субъектов доступа к виртуальной инфраструктуре",
        "docs": "Приказ ФСТЭК России №17 (2013), №21 (2013)",
        "note": "Защита виртуализированных сред",
    },
}

# Convenience: short regulatory reference string for display
def _reg(code: str) -> str:
    r = REGULATORY.get(code, {})
    return f"{code} — {r.get('title', '')} ({r.get('docs', '')})"


# ── Recommendation dataclass ───────────────────────────────────────────────

@dataclass
class Recommendation:
    rec_type: str        # update | config | restrict | monitor | auth | isolate | urgent
    title: str
    description: str
    priority: int        # 1 = critical, 2 = high, 3 = medium, 4 = low, 5 = info
    regulatory_ref: str  # short code, e.g. "АНЗ.2"
    regulatory_text: str # full reference string


# ── SLA table aligned with ФСТЭК АНЗ.1 ────────────────────────────────────
# Recommended remediation timeframes based on FSTEC guidance and BDU practice

SLA_BY_CVSS = {
    "critical": {"max_days": 24, "label": "24 часа",  "cvss_min": 9.0},
    "high":     {"max_days": 7,  "label": "7 дней",   "cvss_min": 7.0},
    "medium":   {"max_days": 30, "label": "30 дней",  "cvss_min": 4.0},
    "low":      {"max_days": 90, "label": "90 дней",  "cvss_min": 0.0},
}


def cvss_severity(cvss: float) -> str:
    if cvss >= 9.0: return "critical"
    if cvss >= 7.0: return "high"
    if cvss >= 4.0: return "medium"
    return "low"


def cvss_to_priority(cvss: float) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4}[cvss_severity(cvss)]


# ── Main generation function ───────────────────────────────────────────────

def generate(
    cve_id: str,
    package_name: str,
    version: str = "",
    cvss: float = 0.0,
    epss: float = 0.0,
    in_kev: bool = False,
    description: str = "",
) -> list[Recommendation]:
    """
    Return a list of Recommendation objects for a (CVE, package) combination.
    Recommendations are ordered by priority (1 = most urgent first).
    """
    recs: list[Recommendation] = []
    desc = (description or "").lower()
    pkg  = (package_name or "").lower()
    pri  = cvss_to_priority(cvss)
    sev  = cvss_severity(cvss)
    sla  = SLA_BY_CVSS[sev]["label"]

    # ── 0. KEV / активно эксплуатируемая (всегда первая) ─────────────────
    if in_kev:
        recs.append(Recommendation(
            rec_type="urgent",
            title=f"СРОЧНО: уязвимость активно эксплуатируется (CISA KEV)",
            description=(
                f"{cve_id} включена в каталог CISA Known Exploited Vulnerabilities — "
                "применяется злоумышленниками в реальных атаках прямо сейчас. "
                "Согласно требованиям ФСТЭК (АНЗ.1), устранение критичных уязвимостей "
                "должно быть выполнено незамедлительно. "
                "Если патч ещё недоступен — изолируйте хост или отключите уязвимый сервис."
            ),
            priority=1,
            regulatory_ref="АНЗ.1",
            regulatory_text=_reg("АНЗ.1"),
        ))

    # ── 1. Обновление пакета (всегда) ────────────────────────────────────
    upgrade_cmd = _upgrade_command(pkg)
    recs.append(Recommendation(
        rec_type="update",
        title=f"Установить исправленную версию пакета {package_name}",
        description=(
            f"Основное действие по устранению {cve_id}: обновить {package_name} "
            f"(текущая версия: {version or 'неизвестна'}) до версии, "
            f"содержащей исправление уязвимости. "
            f"{upgrade_cmd} "
            f"После обновления — перезапустить зависимые сервисы. "
            f"Срок устранения согласно ФСТЭК АНЗ.2: {sla}."
        ),
        priority=pri,
        regulatory_ref="АНЗ.2",
        regulatory_text=_reg("АНЗ.2"),
    ))

    # ── 2. Сетевая доступность / RCE ─────────────────────────────────────
    if _match(desc, ["remote code execution", "rce", "уязвимость позволяет",
                     "remote", "network", "http", "heap overflow", "buffer overflow",
                     "use after free", "stack overflow"]):
        recs.append(Recommendation(
            rec_type="restrict",
            title="Ограничить сетевой доступ к уязвимому сервису",
            description=(
                f"{cve_id} эксплуатируется удалённо без аутентификации. "
                "До установки патча: ограничьте доступ к порту сервиса "
                "межсетевым экраном — разрешите подключения только с доверенных адресов. "
                "Примеры команд:\n"
                "  iptables -A INPUT -p tcp --dport <PORT> -s <TRUSTED_NET> -j ACCEPT\n"
                "  iptables -A INPUT -p tcp --dport <PORT> -j DROP"
            ),
            priority=min(pri, 2),
            regulatory_ref="УПД.3",
            regulatory_text=_reg("УПД.3"),
        ))

    # ── 3. Повышение привилегий ───────────────────────────────────────────
    if _match(desc, ["privilege escalation", "local privilege", "elevation of privilege",
                     "local root", "sudo", "setuid", "suid", "sgid", "cap_", "capabilities"]):
        recs.append(Recommendation(
            rec_type="config",
            title="Ограничить привилегии процессов и бинарных файлов",
            description=(
                f"{cve_id} позволяет локальному пользователю повысить привилегии до root. "
                "Проверьте SUID/SGID файлы пакета:\n"
                f"  find / -name '{pkg}*' -perm /6000 -ls\n"
                "Удалите избыточные флаги:\n"
                f"  chmod -s /usr/bin/<binary>\n"
                "Ограничьте sudo-правила в /etc/sudoers: запрет выполнения "
                "конкретных команд для непривилегированных пользователей."
            ),
            priority=min(pri, 2),
            regulatory_ref="ИАФ.3",
            regulatory_text=_reg("ИАФ.3"),
        ))

    # ── 4. Обход аутентификации ───────────────────────────────────────────
    if _match(desc, ["authentication bypass", "auth bypass", "improper authentication",
                     "missing authentication", "unauthenticated", "without authentication",
                     "unauthorized access"]):
        recs.append(Recommendation(
            rec_type="auth",
            title="Усилить аутентификацию и контроль доступа",
            description=(
                f"{cve_id} позволяет обойти аутентификацию. "
                "Проверьте конфигурацию сервиса: убедитесь, что все эндпоинты "
                "требуют аутентификации. Отключите анонимный доступ. "
                "При возможности включите двухфакторную аутентификацию (2FA/MFA). "
                "Ротация всех секретов и токенов, которые могли быть скомпрометированы."
            ),
            priority=min(pri, 2),
            regulatory_ref="ИАФ.1",
            regulatory_text=_reg("ИАФ.1"),
        ))

    # ── 5. Инъекции (SQL, команды, LDAP, XPATH) ───────────────────────────
    if _match(desc, ["sql injection", "command injection", "os command injection",
                     "code injection", "ldap injection", "xpath injection",
                     "server-side template injection", "ssti"]):
        recs.append(Recommendation(
            rec_type="config",
            title="Применить WAF и ограничить входные данные",
            description=(
                f"{cve_id} — уязвимость типа «инъекция». "
                "Немедленные меры: разверните WAF перед уязвимым сервисом "
                "(ModSecurity, nginx + lua, или облачный WAF). "
                "Временно отключите функциональность, в которой эксплуатируется уязвимость. "
                "Проверьте и ограничьте права учётной записи, под которой работает сервис "
                "(принцип наименьших привилегий для DB-пользователя)."
            ),
            priority=min(pri, 2),
            regulatory_ref="УПД.3",
            regulatory_text=_reg("УПД.3"),
        ))

    # ── 6. Путь обхода / произвольное чтение файлов ───────────────────────
    if _match(desc, ["path traversal", "directory traversal", "arbitrary file read",
                     "local file inclusion", "lfi", "file disclosure",
                     "arbitrary file", "information disclosure"]):
        recs.append(Recommendation(
            rec_type="config",
            title="Ограничить доступ к файловой системе (chroot / контейнер)",
            description=(
                f"{cve_id} позволяет читать произвольные файлы сервера. "
                "Запустите сервис в изолированной файловой системе:\n"
                "  — chroot-окружение или systemd DynamicUser=yes / RootDirectory=\n"
                "  — Docker/Podman контейнер с монтированием только необходимых директорий\n"
                "Проверьте права на критичные файлы:\n"
                "  chmod 600 /etc/passwd /etc/shadow /etc/<service>.conf"
            ),
            priority=pri,
            regulatory_ref="ЗТС.3",
            regulatory_text=_reg("ЗТС.3"),
        ))

    # ── 7. Криптография / TLS / SSL ───────────────────────────────────────
    if _match(desc, ["ssl", "tls", "cipher", "cryptographic", "weak encryption",
                     "certificate", "man-in-the-middle", "mitm", "padding oracle",
                     "downgrade"]) or \
       any(x in pkg for x in ["openssl", "gnutls", "nss", "libssl", "mbedtls",
                               "botan", "cryptlib", "nettle"]):
        recs.append(Recommendation(
            rec_type="config",
            title="Обновить криптографическую конфигурацию — отключить устаревшие протоколы",
            description=(
                f"{cve_id} затрагивает криптографические компоненты. "
                "Отключите устаревшие протоколы и слабые шифры:\n"
                "  nginx: ssl_protocols TLSv1.2 TLSv1.3;\n"
                "         ssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n"
                "  Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                "          SSLCipherSuite HIGH:!aNULL:!MD5:!RC4:!DES\n"
                "Проверьте конфигурацию: testssl.sh или ssllabs.com."
            ),
            priority=pri,
            regulatory_ref="ЗИС.3",
            regulatory_text=_reg("ЗИС.3"),
        ))

    # ── 8. Отказ в обслуживании (DoS) ────────────────────────────────────
    if _match(desc, ["denial of service", " dos ", "null pointer dereference",
                     "memory exhaustion", "infinite loop", "crash", "deadlock",
                     "resource exhaustion", "out of memory"]):
        recs.append(Recommendation(
            rec_type="isolate",
            title="Настроить rate-limiting и автоматическое восстановление сервиса",
            description=(
                f"{cve_id} может вызвать отказ в обслуживании. "
                "До установки патча:\n"
                "  1. Rate-limiting: iptables -A INPUT -p tcp --dport <PORT> -m limit "
                "--limit 100/min -j ACCEPT\n"
                "  2. Автоперезапуск: в /etc/systemd/system/<service>.service:\n"
                "     [Service]\n     Restart=always\n     RestartSec=5\n"
                "  3. Мониторинг ресурсов: настройте алерт при потреблении "
                "CPU/RAM > 90% для сервиса."
            ),
            priority=min(pri + 1, 5),
            regulatory_ref="РСБ.2",
            regulatory_text=_reg("РСБ.2"),
        ))

    # ── 9. Мониторинг целостности (для CVSS >= 7.0) ───────────────────────
    if cvss >= 7.0:
        recs.append(Recommendation(
            rec_type="monitor",
            title="Включить аудит событий безопасности и контроль целостности",
            description=(
                f"Для уязвимости высокой критичности (CVSS {cvss:.1f}) требуется "
                "усиленный мониторинг:\n"
                f"  auditctl -w /usr/lib -p wa -k pkg_{pkg[:20]}_change\n"
                "  auditctl -w /etc -p wa -k config_change\n"
                "Установите AIDE или Tripwire для контроля целостности файлов.\n"
                "Проверьте наличие признаков эксплуатации в логах: "
                f"  grep -i '{cve_id}\\|exploit\\|shellcode' /var/log/syslog"
            ),
            priority=min(pri + 1, 5),
            regulatory_ref="РСБ.2",
            regulatory_text=_reg("РСБ.2"),
        ))

    # ── 10. Контроль целостности ПО (всегда для критичных пакетов) ────────
    if cvss >= 9.0 or in_kev:
        recs.append(Recommendation(
            rec_type="monitor",
            title="Верификация целостности установленного пакета",
            description=(
                f"После устранения {cve_id} — проверьте целостность пакета:\n"
                "  Debian/Ubuntu: dpkg --verify <package>\n"
                "  RHEL/CentOS:   rpm -V <package>\n"
                "Убедитесь, что установлен пакет из доверенного репозитория "
                "(проверка GPG-подписи). Зафиксируйте факт устранения в системе "
                "управления уязвимостями согласно требованиям ФСТЭК АНЗ.1."
            ),
            priority=min(pri + 2, 5),
            regulatory_ref="ОЦЛ.1",
            regulatory_text=_reg("ОЦЛ.1"),
        ))

    # Сортировка по приоритету
    recs.sort(key=lambda r: r.priority)
    return recs


# ── Helpers ────────────────────────────────────────────────────────────────

def _match(text: str, keywords: list[str]) -> bool:
    return any(kw in text for kw in keywords)


def _upgrade_command(pkg: str) -> str:
    """Return a likely upgrade command hint based on package name."""
    if any(x in pkg for x in ["python", "pip", "django", "flask", "fastapi"]):
        return f"pip install --upgrade {pkg}  # или обновите через пакетный менеджер ОС."
    if any(x in pkg for x in ["npm", "node", "js"]):
        return f"npm update {pkg}  # или через apt/yum."
    if any(x in pkg for x in ["gem", "ruby"]):
        return f"gem update {pkg}  # или через пакетный менеджер ОС."
    return (
        f"apt-get update && apt-get install --only-upgrade {pkg}  # для Debian/Ubuntu\n"
        f"  yum update {pkg}  # для RHEL/CentOS\n"
        f"  apk upgrade {pkg}  # для Alpine"
    )
