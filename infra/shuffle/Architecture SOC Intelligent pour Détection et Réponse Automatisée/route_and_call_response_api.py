import json
import urllib.error
import urllib.request


API_BASE_DEFAULT = "http://192.168.99.15:8000"
STATIC_TOKEN = "42c5446b57a840d1bc87c8c7eef77f25975e515701b1a1dff91219cdfbe456fb"


def to_obj(v):
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s or s.startswith("$"):
            return {}
        try:
            x = json.loads(s)
            return x if isinstance(x, dict) else {}
        except Exception:
            return {}
    return {}


def unwrap(step):
    data = to_obj(step)
    if not data:
        return {}
    message = to_obj(data.get("message"))
    return message if message else data


def get_node(input_data, name):
    candidates = (
        input_data.get(name),
        input_data.get("$" + name),
        input_data.get(name.lower()),
        input_data.get(name.upper()),
    )
    for item in candidates:
        node = unwrap(item or {})
        if node:
            return node

    template_message = to_obj(r"""$build_response_payload.message""")
    if name == "build_response_payload" and template_message:
        return template_message

    template_raw = to_obj(r"""$build_response_payload""")
    if name == "build_response_payload" and template_raw:
        node = unwrap(template_raw)
        if node:
            return node

    return {}


def main(input_data):
    build = get_node(input_data, "build_response_payload")
    payload = to_obj(build.get("payload"))
    meta = to_obj(build.get("meta"))
    target_os = str(build.get("target_os") or "").lower().strip()

    priority = str(meta.get("priority") or "").upper().strip()
    approved_by = str(payload.get("approved_by") or "").strip()
    host = str(payload.get("host") or "").strip()
    action = str(payload.get("action") or "").strip()

    trigger = (
        priority in ("HIGH", "CRITICAL")
        and approved_by != ""
        and host != ""
        and action != ""
    )
    if not trigger:
        return {
            "response_executed": False,
            "response_status": "skipped",
            "reason": "policy_not_met",
            "request_payload": payload,
            "debug": {
                "has_build": bool(build),
                "priority": priority,
                "approved_by": approved_by,
                "host": host,
                "action": action,
                "target_os": target_os,
            },
        }

    if target_os == "linux":
        endpoint_path = "/respond/linux"
    elif target_os == "windows":
        endpoint_path = "/respond"
    else:
        return {
            "response_executed": False,
            "response_status": "skipped",
            "reason": "unknown_target_os",
            "request_payload": payload,
        }

    api_base = str(input_data.get("RESPONSE_API_BASE") or API_BASE_DEFAULT).rstrip("/")
    endpoint = api_base + endpoint_path

    token = str(input_data.get("SOC_API_TOKEN") or "").strip()
    if not token:
        token = STATIC_TOKEN.strip()
    if not token:
        return {
            "response_executed": False,
            "response_status": "failed",
            "reason": "missing_SOC_API_TOKEN",
            "endpoint": endpoint,
            "request_payload": payload,
        }

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={"Content-Type": "application/json", "X-API-Token": token},
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(raw) if raw else {}
            ok = str(parsed.get("status") or "").lower() == "completed"
            return {
                "response_executed": ok,
                "response_status": "completed" if ok else "failed",
                "endpoint": endpoint,
                "request_payload": payload,
                "response_raw": parsed,
            }
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            parsed_error = json.loads(raw) if raw else {}
        except Exception:
            parsed_error = {"raw": raw}
        return {
            "response_executed": False,
            "response_status": "failed",
            "endpoint": endpoint,
            "http_status": e.code,
            "error_body": parsed_error,
            "request_payload": payload,
        }
    except Exception as e:
        return {
            "response_executed": False,
            "response_status": "failed",
            "endpoint": endpoint,
            "error": str(e),
            "request_payload": payload,
        }


incoming = globals().get("inputData")
if incoming is None:
    incoming = globals().get("data")
if incoming is None:
    incoming = globals().get("params")
if incoming is None or not isinstance(incoming, dict):
    incoming = {}

output = main(incoming)
print(json.dumps(output, ensure_ascii=False))
