from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import re
import shlex
import socket
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("soc-response")

TOKEN = os.getenv("SOC_API_TOKEN", "")
WINRM_ALLOWED_HOSTS = {
    value.strip()
    for value in os.getenv("WINRM_ALLOWED_HOSTS", "").split(",")
    if value.strip()
}
LINUX_ALLOWED_HOSTS = {
    value.strip()
    for value in os.getenv("LINUX_SSH_ALLOWED_HOSTS", "").split(",")
    if value.strip()
}
app = FastAPI(title="API de réponse SOC", version="1.0.0")


class RespondRequest(BaseModel):
    host: str
    action: Literal["isolate", "kill_process", "disable_user"]
    approved_by: str = Field(min_length=2, max_length=80)
    case_id: str | None = Field(default=None, max_length=100)
    param: str | None = Field(default=None, max_length=64)

    @field_validator("host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError as exc:
            raise ValueError("L'hôte doit être une adresse IP autorisée.") from exc

    @field_validator("approved_by", "case_id")
    @classmethod
    def trim_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("La valeur ne peut pas être vide.")
        if not re.fullmatch(r"[A-Za-z0-9_.@ -]{2,100}", cleaned):
            raise ValueError("La valeur contient des caractères non autorisés.")
        return cleaned

    @field_validator("param")
    @classmethod
    def validate_parameter(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", cleaned):
            raise ValueError("paramètre invalide : seuls lettres, chiffres, '.', '_' et '-' sont admis.")
        return cleaned


def _authorize(token: str | None) -> None:
    if not TOKEN or TOKEN.startswith("CHANGE_ME") or len(TOKEN) < 32:
        raise HTTPException(status_code=503, detail="SOC_API_TOKEN doit être un secret aléatoire d'au moins 32 caractères.")
    if token is None or not hmac.compare_digest(token, TOKEN):
        raise HTTPException(status_code=401, detail="Token API invalide.")


def _build_script(action: str, param: str | None) -> str:
    if action not in {"isolate", "kill_process", "disable_user"}:
        raise HTTPException(status_code=400, detail="Action non autorisée.")
    if action == "isolate":
        return (
            "if (-not (Get-NetFirewallRule -DisplayName 'SOC-Isolate' "
            "-ErrorAction SilentlyContinue)) { "
            "New-NetFirewallRule -DisplayName 'SOC-Isolate' "
            "-Direction Outbound -Action Block -Profile Any }"
        )
    if not param:
        raise HTTPException(status_code=422, detail="Cette action exige un paramètre valide.")
    allowlist_variable = (
        "WINRM_ALLOWED_PROCESSES" if action == "kill_process" else "WINRM_ALLOWED_USERS"
    )
    allowed_values = {
        value.strip().casefold()
        for value in os.getenv(allowlist_variable, "").split(",")
        if value.strip()
    }
    if param.casefold() not in allowed_values:
        raise HTTPException(status_code=403, detail="Le paramètre n'est pas dans la liste autorisée.")
    if action == "disable_user":
        service_user = os.getenv("WINRM_USER", "").rsplit("\\", maxsplit=1)[-1]
        if param.casefold() == service_user.casefold():
            raise HTTPException(status_code=403, detail="Le compte de service WinRM ne peut pas être désactivé.")
    escaped = param.replace("'", "''")
    if action == "kill_process":
        return f"Stop-Process -Name '{escaped}' -Force -ErrorAction Stop"
    if action == "disable_user":
        return f"Disable-LocalUser -Name '{escaped}' -ErrorAction Stop"
    raise HTTPException(status_code=400, detail="Action non autorisée.")


def _run_winrm(host: str, script: str) -> dict[str, str | int]:
    if os.getenv("WINRM_ENABLED", "false").lower() != "true":
        raise HTTPException(status_code=503, detail="WinRM est désactivé.")
    port = os.getenv("WINRM_PORT", "5986")
    if port != "5986":
        raise HTTPException(status_code=503, detail="Seul WinRM sur HTTPS (port 5986) est autorisé.")
    user = os.getenv("WINRM_USER", "")
    password = os.getenv("WINRM_PASS", "")
    if not user or not password:
        raise HTTPException(status_code=503, detail="Les identifiants WinRM ne sont pas configurés.")

    ca_cert = os.getenv("WINRM_CA_CERT", "")
    if ca_cert and not os.path.isfile(ca_cert):
        raise HTTPException(status_code=503, detail="Le certificat CA WinRM configuré est introuvable.")
    if ca_cert:
        os.environ["REQUESTS_CA_BUNDLE"] = ca_cert
    endpoint = f"https://{host}:{port}/wsman"
    import winrm
    try:
        session = winrm.Session(
            endpoint,
            auth=(user, password),
            transport=os.getenv("WINRM_TRANSPORT", "ntlm"),
            server_cert_validation="validate",
            operation_timeout_sec=20,
            read_timeout_sec=30,
        )
        result = session.run_ps(script)
    except winrm.exceptions.WinRMError as exc:
        logger.exception("Échec WinRM vers l'hôte autorisé %s", host)
        raise HTTPException(status_code=502, detail="La commande WinRM a échoué.") from exc
    stdout = result.std_out.decode("utf-8", errors="replace")[:4000]
    stderr = result.std_err.decode("utf-8", errors="replace")[:4000]
    if result.status_code != 0:
        raise HTTPException(status_code=502, detail="La commande distante a échoué.")
    return {"status": result.status_code, "stdout": stdout, "stderr": stderr}


def _linux_base_command(command: str) -> str:
    if os.getenv("LINUX_SSH_USE_SUDO", "true").lower() == "true":
        return f"sudo -n {command}"
    return command


def _build_linux_command(action: str, param: str | None) -> str:
    if action not in {"isolate", "kill_process", "disable_user"}:
        raise HTTPException(status_code=400, detail="Action non autorisée.")
    if action == "isolate":
        isolate_script = (
            "bash -lc "
            "'if command -v nft >/dev/null 2>&1; then "
            "nft list table inet soc_isolate >/dev/null 2>&1 || nft add table inet soc_isolate; "
            "nft list chain inet soc_isolate output >/dev/null 2>&1 || "
            "nft add chain inet soc_isolate output \"{ type filter hook output priority 0; policy drop; }\"; "
            "nft flush chain inet soc_isolate output; "
            "nft add rule inet soc_isolate output oifname lo accept; "
            "nft add rule inet soc_isolate output ct state established,related accept; "
            "else "
            "iptables -N SOC-ISOLATE >/dev/null 2>&1 || true; "
            "iptables -F SOC-ISOLATE; "
            "iptables -A SOC-ISOLATE -o lo -j ACCEPT; "
            "iptables -A SOC-ISOLATE -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; "
            "iptables -A SOC-ISOLATE -j DROP; "
            "iptables -C OUTPUT -j SOC-ISOLATE >/dev/null 2>&1 || iptables -I OUTPUT 1 -j SOC-ISOLATE; "
            "fi'"
        )
        return _linux_base_command(isolate_script)
    if not param:
        raise HTTPException(status_code=422, detail="Cette action exige un paramètre valide.")
    allowlist_variable = (
        "LINUX_SSH_ALLOWED_PROCESSES" if action == "kill_process" else "LINUX_SSH_ALLOWED_USERS"
    )
    allowed_values = {
        value.strip().casefold()
        for value in os.getenv(allowlist_variable, "").split(",")
        if value.strip()
    }
    if param.casefold() not in allowed_values:
        raise HTTPException(status_code=403, detail="Le paramètre n'est pas dans la liste autorisée.")
    if action == "disable_user":
        service_user = os.getenv("LINUX_SSH_USER", "").split("@", maxsplit=1)[0]
        if param.casefold() == service_user.casefold():
            raise HTTPException(status_code=403, detail="Le compte de service SSH ne peut pas être désactivé.")
    escaped = shlex.quote(param)
    if action == "kill_process":
        return _linux_base_command(f"pkill -TERM -x -- {escaped}")
    if action == "disable_user":
        return _linux_base_command(f"usermod -L -- {escaped}")
    raise HTTPException(status_code=400, detail="Action non autorisée.")


def _run_linux_ssh(host: str, command: str) -> dict[str, str | int]:
    if os.getenv("LINUX_SSH_ENABLED", "false").lower() != "true":
        raise HTTPException(status_code=503, detail="SSH Linux est désactivé.")
    user = os.getenv("LINUX_SSH_USER", "")
    if not user:
        raise HTTPException(status_code=503, detail="Le compte SSH Linux n'est pas configuré.")
    password = os.getenv("LINUX_SSH_PASS", "")
    key_path = os.getenv("LINUX_SSH_KEY_PATH", "")
    if not password and not key_path:
        raise HTTPException(
            status_code=503,
            detail="Configurer LINUX_SSH_PASS ou LINUX_SSH_KEY_PATH pour l'authentification SSH Linux.",
        )
    if key_path and not os.path.isfile(key_path):
        raise HTTPException(status_code=503, detail="La clé privée SSH Linux configurée est introuvable.")
    known_hosts_path = os.getenv("LINUX_SSH_KNOWN_HOSTS", "/app/certs/linux_known_hosts")
    if not os.path.isfile(known_hosts_path):
        raise HTTPException(status_code=503, detail="Le fichier known_hosts Linux configuré est introuvable.")
    try:
        port = int(os.getenv("LINUX_SSH_PORT", "22"))
    except ValueError as exc:
        raise HTTPException(status_code=503, detail="LINUX_SSH_PORT est invalide.") from exc
    if port < 1 or port > 65535:
        raise HTTPException(status_code=503, detail="LINUX_SSH_PORT est hors plage.")

    import paramiko

    client = paramiko.SSHClient()
    client.load_host_keys(known_hosts_path)
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        connect_kwargs: dict[str, object] = {
            "hostname": host,
            "port": port,
            "username": user,
            "timeout": 10,
            "banner_timeout": 10,
            "auth_timeout": 10,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if key_path:
            connect_kwargs["key_filename"] = key_path
        if password:
            connect_kwargs["password"] = password
        client.connect(**connect_kwargs)
        stdin, stdout_stream, stderr_stream = client.exec_command(command, timeout=30)
        stdin.close()
        exit_code = stdout_stream.channel.recv_exit_status()
        stdout = stdout_stream.read().decode("utf-8", errors="replace")[:4000]
        stderr = stderr_stream.read().decode("utf-8", errors="replace")[:4000]
    except paramiko.AuthenticationException as exc:
        logger.exception("Échec d'authentification SSH Linux vers %s", host)
        raise HTTPException(status_code=502, detail="Authentification SSH Linux échouée.") from exc
    except (paramiko.SSHException, socket.timeout, OSError) as exc:
        logger.exception("Échec SSH Linux vers l'hôte autorisé %s", host)
        raise HTTPException(status_code=502, detail="La commande SSH Linux a échoué.") from exc
    finally:
        client.close()
    if exit_code != 0:
        raise HTTPException(status_code=502, detail="La commande Linux distante a échoué.")
    return {"status": exit_code, "stdout": stdout, "stderr": stderr}


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "winrm_enabled": os.getenv("WINRM_ENABLED", "false").lower() == "true",
        "winrm_allowed_hosts_configured": bool(WINRM_ALLOWED_HOSTS),
        "linux_ssh_enabled": os.getenv("LINUX_SSH_ENABLED", "false").lower() == "true",
        "linux_allowed_hosts_configured": bool(LINUX_ALLOWED_HOSTS),
    }


@app.post("/respond")
def respond(
    request: RespondRequest,
    x_api_token: str | None = Header(default=None),
) -> dict[str, object]:
    _authorize(x_api_token)
    if request.host not in WINRM_ALLOWED_HOSTS:
        logger.warning(
            "Réponse refusée : hôte non autorisé host=%s action=%s by=%s case=%s",
            request.host,
            request.action,
            request.approved_by,
            request.case_id,
        )
        raise HTTPException(status_code=403, detail="Hôte non autorisé.")
    if request.action != "isolate" and not request.param:
        raise HTTPException(status_code=422, detail="Cette action exige un paramètre valide.")

    logger.info(
        "Action approuvée reçue host=%s action=%s param=%s by=%s case=%s",
        request.host,
        request.action,
        request.param,
        request.approved_by,
        request.case_id,
    )
    result = _run_winrm(request.host, _build_script(request.action, request.param))
    return {
        "status": "completed",
        "host": request.host,
        "action": request.action,
        "approved_by": request.approved_by,
        "case_id": request.case_id,
        "result": result,
    }


@app.post("/respond/linux")
def respond_linux(
    request: RespondRequest,
    x_api_token: str | None = Header(default=None),
) -> dict[str, object]:
    _authorize(x_api_token)
    if request.host not in LINUX_ALLOWED_HOSTS:
        logger.warning(
            "Réponse Linux refusée : hôte non autorisé host=%s action=%s by=%s case=%s",
            request.host,
            request.action,
            request.approved_by,
            request.case_id,
        )
        raise HTTPException(status_code=403, detail="Hôte Linux non autorisé.")
    if request.action != "isolate" and not request.param:
        raise HTTPException(status_code=422, detail="Cette action exige un paramètre valide.")

    logger.info(
        "Action Linux approuvée reçue host=%s action=%s param=%s by=%s case=%s",
        request.host,
        request.action,
        request.param,
        request.approved_by,
        request.case_id,
    )
    result = _run_linux_ssh(request.host, _build_linux_command(request.action, request.param))
    return {
        "status": "completed",
        "platform": "linux",
        "host": request.host,
        "action": request.action,
        "approved_by": request.approved_by,
        "case_id": request.case_id,
        "result": result,
    }
