import json
from datetime import datetime


def _to_obj(v):
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


def unwrap_node(node):
    data = _to_obj(node)
    if not data:
        return {}
    msg = _to_obj(data.get("message"))
    return msg if msg else data


def get_node(input_data, name):
    candidates = (
        input_data.get(name),
        input_data.get("$" + name),
        input_data.get(name.lower()),
        input_data.get(name.upper()),
    )
    for item in candidates:
        node = unwrap_node(item or {})
        if node:
            return node

    if name == "route_and_call_response_api":
        template_message = _to_obj(r"""$route_and_call_response_api.message""")
        if template_message:
            return template_message
        template_raw = _to_obj(r"""$route_and_call_response_api""")
        if template_raw:
            node = unwrap_node(template_raw)
            if node:
                return node

    if name == "build_response_payload":
        template_message = _to_obj(r"""$build_response_payload.message""")
        if template_message:
            return template_message
        template_raw = _to_obj(r"""$build_response_payload""")
        if template_raw:
            node = unwrap_node(template_raw)
            if node:
                return node

    return {}


def main(input_data):
    route = get_node(input_data, "route_and_call_response_api")
    build = get_node(input_data, "build_response_payload")

    payload = _to_obj(build.get("payload"))
    meta = _to_obj(build.get("meta"))

    response_status = str(route.get("response_status") or "").strip()
    response_executed = bool(route.get("response_executed", False))
    reason = str(route.get("reason") or "").strip()
    endpoint = str(route.get("endpoint") or "").strip()
    http_status = route.get("http_status")

    if not response_status:
        route_success = bool(
            _to_obj(input_data.get("route_and_call_response_api") or {}).get("success", False)
        )
        response_status = "unknown" if route_success else "failed"

    log_line = (
        "[SOAR] status={status} executed={executed} host={host} action={action} "
        "approved_by={approved} endpoint={endpoint} reason={reason} http_status={http_status}"
    ).format(
        status=response_status,
        executed=str(response_executed).lower(),
        host=str(payload.get("host") or ""),
        action=str(payload.get("action") or ""),
        approved=str(payload.get("approved_by") or ""),
        endpoint=endpoint,
        reason=reason,
        http_status=str(http_status) if http_status is not None else ""
    )

    return {
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "response_status": response_status,
        "response_executed": response_executed,
        "reason": reason,
        "endpoint": endpoint,
        "http_status": http_status,
        "priority": str(meta.get("priority") or "").upper(),
        "request_payload": route.get("request_payload") or payload,
        "response_raw": route.get("response_raw") or {},
        "error_body": route.get("error_body") or {},
        "log_line": log_line
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