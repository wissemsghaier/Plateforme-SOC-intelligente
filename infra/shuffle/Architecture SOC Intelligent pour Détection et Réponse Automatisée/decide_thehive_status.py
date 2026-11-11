import json


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


def unwrap(node):
    d = to_obj(node)
    if not d:
        return {}
    m = to_obj(d.get("message"))
    return m if m else d


route = unwrap(to_obj(r"""$route_and_call_response_api"""))
trace = unwrap(to_obj(r"""$build_thehive_trace"""))

response_status = str(route.get("response_status") or "").lower().strip()
response_executed = bool(route.get("response_executed", False))

if response_status == "completed" and response_executed:
    status_to_set = "InProgress"
else:
    status_to_set = "Pending"

out = {
    "thehive_ref": str(trace.get("thehive_ref") or "").strip(),
    "status_to_set": status_to_set,
    "trace_tag": str(trace.get("trace_tag") or "").strip(),
    "trace_text": str(trace.get("trace_text") or "").strip(),
}
print(json.dumps(out, ensure_ascii=False))