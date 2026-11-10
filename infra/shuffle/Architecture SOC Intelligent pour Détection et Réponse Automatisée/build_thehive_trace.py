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


def first_non_empty_str(values):
    for v in values:
        s = str(v or "").strip()
        if s:
            return s
    return ""


def find_id_deep(obj):
    if isinstance(obj, dict):
        direct = first_non_empty_str(
            [obj.get("_id"), obj.get("id"), obj.get("alert_id"), obj.get("alertId")]
        )
        if direct:
            return direct
        for _, v in obj.items():
            nested = find_id_deep(v)
            if nested:
                return nested
        return ""
    if isinstance(obj, list):
        for item in obj:
            nested = find_id_deep(item)
            if nested:
                return nested
    return ""


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

    if name == "log_response_result":
        t = _to_obj(r"""$log_response_result.message""")
        if t:
            return t
        t2 = _to_obj(r"""$log_response_result""")
        if t2:
            node = unwrap_node(t2)
            if node:
                return node

    if name == "build_response_payload":
        t = _to_obj(r"""$build_response_payload.message""")
        if t:
            return t
        t2 = _to_obj(r"""$build_response_payload""")
        if t2:
            node = unwrap_node(t2)
            if node:
                return node

    if name == "create_thehive_alert":
        t = _to_obj(r"""$create_thehive_alert.message""")
        if t:
            return t
        t2 = _to_obj(r"""$create_thehive_alert""")
        if t2:
            node = unwrap_node(t2)
            if node:
                return node

    if name == "update_thehive_alert":
        t = _to_obj(r"""$update_thehive_alert.message""")
        if t:
            return t
        t2 = _to_obj(r"""$update_thehive_alert""")
        if t2:
            node = unwrap_node(t2)
            if node:
                return node

    return {}


def main(input_data):
    log_result = get_node(input_data, "log_response_result")
    build = get_node(input_data, "build_response_payload")
    created = get_node(input_data, "create_thehive_alert")
    updated = get_node(input_data, "update_thehive_alert")

    payload = _to_obj(build.get("payload"))
    meta = _to_obj(build.get("meta"))
    created_body = _to_obj(created.get("body"))
    updated_body = _to_obj(updated.get("body"))

    thehive_ref = first_non_empty_str(
        [
            payload.get("case_id"),
            find_id_deep(created_body),
            find_id_deep(created),
            find_id_deep(updated_body),
            find_id_deep(updated),
            find_id_deep(input_data.get("create_thehive_alert")),
            find_id_deep(input_data.get("update_thehive_alert")),
        ]
    )

    response_status = str(log_result.get("response_status") or "unknown").strip()
    response_executed = bool(log_result.get("response_executed", False))
    reason = str(log_result.get("reason") or "").strip()
    endpoint = str(log_result.get("endpoint") or "").strip()
    http_status = log_result.get("http_status")
    priority = str(meta.get("priority") or "").upper().strip()
    target_os = str(build.get("target_os") or "").strip()

    host = str(payload.get("host") or "").strip()
    action = str(payload.get("action") or "").strip()
    approved_by = str(payload.get("approved_by") or "").strip()
    param = str(payload.get("param") or "").strip()

    ts = datetime.utcnow().isoformat() + "Z"
    trace_text = (
        "[SOAR Response Trace]\n"
        "time_utc: {ts}\n"
        "status: {status}\n"
        "executed: {executed}\n"
        "priority: {priority}\n"
        "target_os: {target_os}\n"
        "host: {host}\n"
        "action: {action}\n"
        "param: {param}\n"
        "approved_by: {approved_by}\n"
        "endpoint: {endpoint}\n"
        "http_status: {http_status}\n"
        "reason: {reason}\n"
    ).format(
        ts=ts,
        status=response_status,
        executed=str(response_executed).lower(),
        priority=priority,
        target_os=target_os,
        host=host,
        action=action,
        param=param,
        approved_by=approved_by,
        endpoint=endpoint,
        http_status=str(http_status) if http_status is not None else "",
        reason=reason,
    )

    trace_tag = "soar-response-" + (response_status.lower() if response_status else "unknown")
    trace_text_json = json.dumps(trace_text, ensure_ascii=False)[1:-1]

    return {
        "thehive_ref": thehive_ref,
        "trace_text": trace_text,
        "trace_text_json": trace_text_json,
        "trace_tag": trace_tag,
        "response_status": response_status,
        "debug_ref_found": bool(thehive_ref),
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
