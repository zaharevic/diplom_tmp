"""SSH-based package collector.

Connects to a remote host via SSH, detects the OS family,
and returns a list of installed packages as dicts {name, version}.
No FastAPI dependency — pure Python, testable independently.
"""

import logging
import socket
from typing import Optional

logger = logging.getLogger(__name__)

# Commands to collect packages per OS family
_COLLECT_COMMANDS = {
    "debian": "dpkg-query -W -f='${Package} ${Version}\\n' 2>/dev/null",
    "rpm":    "rpm -qa --queryformat '%{NAME} %{VERSION}-%{RELEASE}\\n' 2>/dev/null",
    "alpine": "apk info -v 2>/dev/null",
}

# Timeout constants (seconds)
CONNECT_TIMEOUT = 10
EXEC_TIMEOUT = 60


class SSHScanError(Exception):
    """Raised when SSH scanning fails."""


def scan_host(
    hostname: str,
    port: int,
    username: str,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    key_passphrase: Optional[str] = None,
    use_sudo: bool = False,
) -> list[dict]:
    """Connect to hostname via SSH and return installed packages.

    Returns a list of {"name": str, "version": str} dicts.
    Raises SSHScanError on any failure.
    """
    try:
        import paramiko
    except ImportError:
        raise SSHScanError("paramiko not installed — run: pip install paramiko")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        _connect(client, hostname, port, username, password, key_path, key_passphrase)
        os_family = _detect_os(client, use_sudo)
        logger.info(f"[ssh] {hostname}: detected OS family '{os_family}'")
        packages = _collect_packages(client, os_family, use_sudo)
        logger.info(f"[ssh] {hostname}: collected {len(packages)} packages")
        return packages
    except SSHScanError:
        raise
    except paramiko.AuthenticationException as e:
        raise SSHScanError(f"Authentication failed: {e}") from e
    except (socket.timeout, TimeoutError) as e:
        raise SSHScanError(f"Connection timed out: {e}") from e
    except Exception as e:
        raise SSHScanError(f"SSH error: {e}") from e
    finally:
        client.close()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _connect(client, hostname, port, username, password, key_path, key_passphrase):
    """Open SSH connection. Tries key auth first, then password."""
    import paramiko

    pkey = None
    if key_path:
        try:
            pkey = paramiko.RSAKey.from_private_key_file(key_path, password=key_passphrase)
        except paramiko.ssh_exception.SSHException:
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(key_path, password=key_passphrase)
            except Exception:
                pass
        except FileNotFoundError:
            raise SSHScanError(f"Key file not found: {key_path}")

    try:
        client.connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            timeout=CONNECT_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=15,
        )
    except Exception as e:
        raise SSHScanError(f"Cannot connect to {hostname}:{port} — {e}") from e


def _exec(client, command: str, timeout: int = EXEC_TIMEOUT) -> tuple[str, str, int]:
    """Run a command, return (stdout, stderr, exit_code)."""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    code = stdout.channel.recv_exit_status()
    return out, err, code


def _detect_os(client, use_sudo: bool) -> str:
    """Return 'debian', 'rpm', 'alpine', or raise SSHScanError."""
    out, _, _ = _exec(client, "cat /etc/os-release 2>/dev/null || true")
    os_release = out.lower()

    if any(x in os_release for x in ("ubuntu", "debian", "raspbian", "kali", "mint")):
        return "debian"
    if any(x in os_release for x in ("rhel", "centos", "fedora", "rocky", "almalinux", "oracle")):
        return "rpm"
    if "alpine" in os_release:
        return "alpine"

    # Fallback: check which package manager is available
    for cmd, family in (("dpkg", "debian"), ("rpm", "rpm"), ("apk", "alpine")):
        out, _, code = _exec(client, f"which {cmd} 2>/dev/null")
        if code == 0 and out:
            return family

    raise SSHScanError("Cannot determine OS/package manager on remote host")


def _collect_packages(client, os_family: str, use_sudo: bool) -> list[dict]:
    """Run the appropriate collect command and parse output."""
    cmd = _COLLECT_COMMANDS[os_family]
    if use_sudo:
        cmd = "sudo -n " + cmd

    out, err, code = _exec(client, cmd)
    if code != 0 and not out:
        raise SSHScanError(f"Package list command failed (exit {code}): {err[:200]}")

    return _parse_packages(out, os_family)


def _parse_packages(raw: str, os_family: str) -> list[dict]:
    """Parse raw package list output into [{name, version}]."""
    packages = []
    seen = set()

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        if os_family == "debian":
            parts = line.split(None, 1)
            if len(parts) == 2:
                name, version = parts[0], parts[1]
            else:
                name, version = parts[0], ""

        elif os_family == "rpm":
            parts = line.rsplit(None, 1)
            if len(parts) == 2:
                name, version = parts[0], _clean_rpm_version(parts[1])
            else:
                name, version = parts[0], ""

        elif os_family == "alpine":
            # apk info -v outputs: name-version
            # Split on last dash that precedes a digit
            name, version = _split_apk_line(line)

        else:
            continue

        key = (name.lower(), version)
        if key in seen:
            continue
        seen.add(key)
        packages.append({"name": name, "version": version})

    return packages


def _clean_rpm_version(version: str) -> str:
    """Remove arch suffixes like .x86_64, .noarch, .el7 from rpm versions."""
    import re
    version = re.sub(r"\.(x86_64|i686|noarch|aarch64|ppc64|s390x)$", "", version)
    return version


def _split_apk_line(line: str) -> tuple[str, str]:
    """Split 'musl-1.2.3-r0' into ('musl', '1.2.3-r0')."""
    import re
    match = re.match(r"^(.+?)-(\d[\w.\-]*)$", line)
    if match:
        return match.group(1), match.group(2)
    return line, ""
