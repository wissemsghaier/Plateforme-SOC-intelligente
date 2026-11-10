import json


def _to_obj(value):
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text or text.startswith("$"):
            return {}
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _unwrap_step(value):
    data = _to_obj(value)
    if not data:
        return {}
    message = _to_obj(data.get("message"))
    return message if message else data


def _to_int(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return default


def _read_step(input_data, name):
    return input_data.get(name) or input_data.get("$" + name) or {}


def main(input_data):
    policy = _unwrap_step(_read_step(input_data, "priority_policy"))
    created = _unwrap_step(_read_step(input_data, "create_thehive_alert"))
    updated = _unwrap_step(_read_step(input_data, "update_thehive_alert"))
    normalized = _unwrap_step(_read_step(input_data, "normalize_event"))
    detected = _unwrap_step(_read_step(input_data, "detect_os_from_wazuh"))

    # Fallback templates Shuffle si besoin
    if not policy:
        policy = _to_obj(r"""$priority_policy.message""")
    if not created:
        created = _to_obj(r"""$create_thehive_alert.message""")
    if not updated:
        updated = _to_obj(r"""$update_thehive_alert.message""")
    if not normalized:
        normalized = _to_obj(r"""$normalize_event.message""")
    if not detected:
        detected = _to_obj(r"""$detect_os_from_wazuh.message""")

    # ---------- PRIORITY ----------
    priority = str(
        policy.get("recommended_priority")
        or policy.get("priority")
        or ""
    ).upper().strip()

    if not priority:
        bucket = str(policy.get("bucket") or "").lower().strip()
        if bucket == "critical":
            priority = "CRITICAL"
        elif bucket == "high":
            priority = "HIGH"
        elif bucket == "medium":
            priority = "MEDIUM"
        elif bucket == "low":
            priority = "LOW"

    if not priority:
        severity = _to_int(policy.get("severity"), 0)
        if severity >= 4:
            priority = "CRITICAL"
        elif severity == 3:
            priority = "HIGH"
        elif severity == 2:
            priority = "MEDIUM"
        elif severity == 1:
            priority = "LOW"

    if not priority:
        # fallback rule level depuis normalize_event si disponible
        rule_id = str(normalized.get("rule_id") or "").strip()
        if rule_id == "110202":
            priority = "CRITICAL"

    # ---------- APPROVAL ----------
    approved_by = str(
        policy.get("approved_by")
        or normalized.get("approved_by")
        or ""
    ).strip()

    if not approved_by and priority in ("HIGH", "CRITICAL"):
        approved_by = "auto-policy"

    # ---------- HOST (priorité detect_os_from_wazuh.response_host) ----------
    host = str(
        detected.get("response_host")
        or normalized.get("response_host")
        or normalized.get("dst_ip")
        or normalized.get("agent_ip")
        or ""
    ).strip()

    # ---------- THEHIVE REF ----------
    # create_thehive_alert retourne souvent body._id
    created_body = _to_obj(created.get("body"))
    updated_body = _to_obj(updated.get("body"))

    thehive_ref = str(
        created_body.get("_id")
        or created.get("id")
        or created.get("alert_id")
        or updated_body.get("_id")
        or updated.get("id")
        or updated.get("alert_id")
        or ""
    ).strip()

    # ---------- TARGET OS (priorité detect_os_from_wazuh.target_os) ----------
    target_os = str(
        detected.get("target_os")
        or normalized.get("target_os")
        or policy.get("target_os")
        or ""
    ).lower().strip()

    if target_os not in ("windows", "linux"):
        target_os = "unknown"

    # ---------- ACTION ----------
    action = str(policy.get("response_action") or "").strip()
    if not action:
        if priority == "CRITICAL":
            action = "isolate"
        elif priority == "HIGH":
            action = "disable_user"

    payload = {
        "host": host,
        "action": action,
        "approved_by": approved_by
    }

    if thehive_ref:
        payload["case_id"] = thehive_ref

    response_param = str(policy.get("response_param") or "").strip()
    if action in ("disable_user", "kill_process") and response_param:
        payload["param"] = response_param

    return {
        "payload": payload,
        "meta": {
            "priority": priority,
            "has_approval": bool(approved_by),
            "has_host": bool(host),
            "has_action": bool(action),
            "has_thehive_ref": bool(thehive_ref)
        },
        "target_os": target_os,
        "debug": {
            "detected_target_os": detected.get("target_os"),
            "detected_response_host": detected.get("response_host"),
            "normalize_dst_ip": normalized.get("dst_ip"),
            "agent_name": normalized.get("agent_name")
        }
    }


incoming = globals().get("inputData")
if incoming is None:
    incoming = globals().get("data")
if incoming is None:
    incoming = globals().get("params")
if incoming is None:
    incoming = {}

if not isinstance(incoming, dict):
    incoming = {}

output = main(incoming)
print(json.dumps(output, ensure_ascii=False))