import json

def parse_any(v):
    if isinstance(v, (dict, list)):
        return v
    if isinstance(v, str):
        s = v.strip()
        if not s or s.startswith("$"):
            return {}
        try:
            return json.loads(s)
        except Exception:
            return {}
    return {}

def classify(os_name, os_platform):
    n = str(os_name or "").lower()
    p = str(os_platform or "").lower()

    if "win" in n or p == "windows":
        return "windows"
    if any(k in n for k in ("linux", "ubuntu", "debian", "centos", "redhat", "alpine", "kali", "amzn")):
        return "linux"
    if p in ("ubuntu", "debian", "centos", "redhat", "alpine", "kali", "amzn", "linux"):
        return "linux"
    return "unknown"

# Lecture directe des outputs des nodes (robuste dans Shuffle)
norm = parse_any(r"""$normalize_event.message""")
items = parse_any(r"""$wazuh_agents_lookup.body.data.affected_items""")

if not isinstance(norm, dict):
    norm = {}
if not isinstance(items, list):
    items = []

dst_ip = str(norm.get("dst_ip") or "").strip()
agent_name = str(norm.get("agent_name") or "").strip().lower()

target_os = "unknown"
matched_agent = {}

# 1) match IP si dst_ip existe
if dst_ip:
    for a in items:
        if not isinstance(a, dict):
            continue
        if str(a.get("ip") or "").strip() != dst_ip:
            continue
        os_obj = a.get("os", {}) if isinstance(a.get("os"), dict) else {}
        target_os = classify(os_obj.get("name"), os_obj.get("platform"))
        matched_agent = {
            "id": a.get("id"),
            "name": a.get("name"),
            "ip": a.get("ip"),
            "os_name": os_obj.get("name"),
            "os_platform": os_obj.get("platform"),
        }
        break

# 2) sinon fallback par nom agent (utile pour alertes Sysmon/EventChannel)
if not matched_agent and agent_name:
    for a in items:
        if not isinstance(a, dict):
            continue
        if str(a.get("name") or "").strip().lower() != agent_name:
            continue
        os_obj = a.get("os", {}) if isinstance(a.get("os"), dict) else {}
        target_os = classify(os_obj.get("name"), os_obj.get("platform"))
        matched_agent = {
            "id": a.get("id"),
            "name": a.get("name"),
            "ip": a.get("ip"),
            "os_name": os_obj.get("name"),
            "os_platform": os_obj.get("platform"),
        }
        break

output = {
    "dst_ip": dst_ip,
    "agent_name": agent_name,
    "target_os": target_os,
    "response_host": matched_agent.get("ip", ""),
    "matched_agent": matched_agent,
    "debug": {
        "norm_ok": bool(norm),
        "items_count": len(items),
        "used_match": "ip" if dst_ip else "agent_name"
    }
}
print(json.dumps(output, ensure_ascii=False))