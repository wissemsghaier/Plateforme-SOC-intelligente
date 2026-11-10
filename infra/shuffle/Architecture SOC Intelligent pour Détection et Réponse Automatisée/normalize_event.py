import json
import re

payload = json.loads(r"""$exec""")

if not isinstance(payload, dict):
    raise ValueError("Le payload doit etre un objet JSON")

af = payload.get("_source") or payload.get("all_fields") or payload
data = af.get("data") or {}
rule = af.get("rule") or {}
agent = af.get("agent") or {}
agent_os = agent.get("os") or {}

def clean(value):
    if value is None:
        return ""
    text = str(value).strip()
    return "" if text.upper() == "NULL" else text

def pick(*values):
    for value in values:
        text = clean(value)
        if text:
            return text
    return ""


def classify_os(os_name):
    hint = clean(os_name).lower()
    if not hint:
        return ""
    if "win" in hint:
        return "windows"
    if any(k in hint for k in ("linux", "ubuntu", "debian", "centos", "redhat", "alpine", "rhel")):
        return "linux"
    return ""

text = pick(af.get("full_log"), payload.get("text"))

match = re.search(
    r"\{([A-Za-z0-9]+)\}\s+"
    r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?"
    r"\s*->\s*"
    r"(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?",
    text,
)

result = {
    "alert_id": pick(af.get("id"), payload.get("id")),
    "timestamp": pick(af.get("timestamp"), payload.get("timestamp")),
    "rule_id": pick(rule.get("id"), payload.get("rule_id")),
    "rule_description": pick(
        rule.get("description"), payload.get("title")
    ),
    "agent_name": clean(agent.get("name")),
    "agent_os_name": pick(
        agent_os.get("name"),
        af.get("agent_os"),
        af.get("os"),
        data.get("os"),
    ),
    "sensor": clean(af.get("location")),
    "sid": clean(data.get("suricata_sid")),
    "src_ip": pick(
        data.get("srcip"), match.group(2) if match else None
    ),
    "dst_ip": pick(
        data.get("dstip"), match.group(4) if match else None
    ),
    "protocol": pick(
        data.get("protocol"),
        data.get("proto"),
        match.group(1) if match else None,
    ).upper(),
    "dst_port": pick(
        data.get("dstport"), match.group(5) if match else None
    ),
}

result["target_os"] = classify_os(result.get("agent_os_name"))

if not result["alert_id"] or not result["rule_id"]:
    raise ValueError("Identifiant evenement ou regle Wazuh absent")

result["valid"] = True

print(json.dumps(result)) 
