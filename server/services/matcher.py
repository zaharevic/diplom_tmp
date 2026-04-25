"""
CVE ↔ version matching service.

Логика:
1. По имени пакета находим ключевые слова для поиска CPE в nvd_local.db
2. Для каждого найденного cpe_match проверяем, попадает ли установленная версия
   в уязвимый диапазон (version_start_including..version_end_excluding и т.д.)
3. Возвращаем только реально применимые CVE с уверенностью совпадения
"""

import re
import sqlite3
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# Импортируем get_cpe_keywords из nvd.py (уже существует)
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from nvd import get_cpe_keywords


def strip_package_version(raw: str) -> str:
    """Убирает эпоху и ревизию из deb/rpm-версий.

    Примеры:
      "1:2.3.4-1ubuntu2.1" → "2.3.4"
      "2.4.51-1.el9"       → "2.4.51"
      "3.11.0~dfsg-1"      → "3.11.0"
    """
    if not raw:
        return ""
    v = raw.strip()
    # убрать эпоху (цифры до первого двоеточия, если после двоеточия есть точка)
    v = re.sub(r'^\d+:', '', v)
    # убрать суффикс пакетного менеджера: -1ubuntu2, .el9, ~dfsg, +dfsg
    v = re.sub(r'[-~+][^0-9].*$', '', v)
    # убрать trailing дефис с числами типа "-1", "-2"
    v = re.sub(r'-\d+$', '', v)
    return v.strip()


def _parse_version(v: str):
    """Парсит версию через packaging.version.Version.
    При неудаче возвращает None (не падает).
    """
    try:
        from packaging.version import Version
        return Version(strip_package_version(v))
    except Exception:
        return None


def version_in_range(
    installed: str,
    start_inc: Optional[str],
    start_exc: Optional[str],
    end_inc:   Optional[str],
    end_exc:   Optional[str],
) -> bool:
    """Возвращает True если installed попадает в уязвимый диапазон.

    Если версия не задана или не парсится — считаем уязвимой (пессимистично).
    Если диапазон не задан вообще — CPE без ограничений, тоже уязвима.
    """
    # нет ни одного ограничения → уязвима для всех версий
    if not any([start_inc, start_exc, end_inc, end_exc]):
        return True

    # неизвестная версия → включаем (лучше лишнее предупреждение, чем пропустить)
    if not installed or installed in ('*', ''):
        return True

    v = _parse_version(installed)
    if v is None:
        return True  # не смогли распарсить — берём пессимистично

    try:
        from packaging.version import Version
        if start_inc and v < Version(strip_package_version(start_inc)):
            return False
        if start_exc and v <= Version(strip_package_version(start_exc)):
            return False
        if end_inc and v > Version(strip_package_version(end_inc)):
            return False
        if end_exc and v >= Version(strip_package_version(end_exc)):
            return False
    except Exception:
        return True  # ошибка парсинга границы → включаем

    return True


def match_package_to_cves(
    pkg_name: str,
    pkg_version: Optional[str],
    nvd_db_path: str,
    limit: int = 200,
) -> list[dict]:
    """Возвращает список CVE, реально применимых к данной версии пакета.

    Каждый элемент:
      cve_id, cvss_score, description, cpe23, confidence
        confidence: 'exact'   — версия точно попала в диапазон
                    'no_range'— диапазон не задан, уязвима по умолчанию
                    'unknown_version' — версия не указана
    """
    if not pkg_name:
        return []

    keywords = get_cpe_keywords(pkg_name)
    if not keywords:
        return []

    results: dict[str, dict] = {}

    try:
        conn = sqlite3.connect(nvd_db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        for kw in keywords:
            c.execute(
                """
                SELECT
                    cve.id          AS cve_id,
                    cve.cvss_score,
                    substr(cve.description, 1, 500) AS description,
                    cm.cpe23,
                    cm.vulnerable,
                    cm.version_start_including,
                    cm.version_start_excluding,
                    cm.version_end_including,
                    cm.version_end_excluding
                FROM cpe_match cm
                JOIN cve ON cve.id = cm.cve_id
                WHERE cm.cpe23 LIKE ?
                  AND cm.vulnerable = 1
                LIMIT ?
                """,
                (f"%{kw}%", limit),
            )

            for row in c.fetchall():
                cve_id = row["cve_id"].upper()

                has_range = any([
                    row["version_start_including"],
                    row["version_start_excluding"],
                    row["version_end_including"],
                    row["version_end_excluding"],
                ])

                if not version_in_range(
                    pkg_version,
                    row["version_start_including"],
                    row["version_start_excluding"],
                    row["version_end_including"],
                    row["version_end_excluding"],
                ):
                    continue  # версия не попадает в диапазон — пропускаем

                if cve_id not in results:
                    if not pkg_version:
                        confidence = "unknown_version"
                    elif not has_range:
                        confidence = "no_range"
                    else:
                        confidence = "exact"

                    results[cve_id] = {
                        "cve_id":      cve_id,
                        "cvss_score":  row["cvss_score"],
                        "description": row["description"],
                        "cpe23":       row["cpe23"],
                        "confidence":  confidence,
                    }

        conn.close()
    except Exception as e:
        logger.error(f"match_package_to_cves error for {pkg_name} {pkg_version}: {e}")

    return list(results.values())
