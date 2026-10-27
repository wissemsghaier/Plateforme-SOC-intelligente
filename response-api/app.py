from __future__ import annotations

import hmac
import ipaddress
import logging
import os
import re
from typing import Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field, field_validator

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("soc-response")

TOKEN = os.getenv("SOC_API_TOKEN", "")
ALLOWED_HOSTS = {
    value.strip()
    for value in os.getenv("WINRM_ALLOWED_HOSTS", "").split(",")
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


@app.get("/health")
def health() -> dict[str, object]:
    return {
        "status": "ok",
        "winrm_enabled": os.getenv("WINRM_ENABLED", "false").lower() == "true",
        "allowed_hosts_configured": bool(ALLOWED_HOSTS),
    }


@app.post("/respond")
def respond(
    request: RespondRequest,
    x_api_token: str | None = Header(default=None),
) -> dict[str, object]:
    _authorize(x_api_token)
    if request.host not in ALLOWED_HOSTS:
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
