import hashlib
import ipaddress
import json
import time

INSTANCE = "wazuh-lab"

event = json.loads(r"""$normalize_event.message""")

if event.get("valid") is not True:
    raise ValueError("Evenement normalise invalide")

def digest(value):
    text = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

protocol = event["protocol"]

identity = {
    "version": 1,
    "instance": INSTANCE,
    "sensor": event["sensor"],
    "rule_id": event["rule_id"],
    "sid": event["sid"],
    "src_ip": event["src_ip"],
    "dst_ip": event["dst_ip"],
    "protocol": protocol,
    "dst_port": "",
}

groupable = bool(
    identity["sensor"]
    and identity["sid"]
    and identity["src_ip"]
    and identity["dst_ip"]
    and protocol in ("TCP", "UDP", "ICMP", "ICMPV6")
)

if groupable:
    identity["src_ip"] = str(ipaddress.ip_address(identity["src_ip"]))
    identity["dst_ip"] = str(ipaddress.ip_address(identity["dst_ip"]))

if protocol in ("TCP", "UDP"):
    port = event["dst_port"]
    if not port:
        groupable = False
    else:
        number = int(port)
        if not 0 <= number <= 65535:
            raise ValueError("Port destination invalide")
        identity["dst_port"] = str(number)

source_ref = f"wazuh:{INSTANCE}:{event['alert_id']}"
event_tag = "wazuh-event:" + digest([INSTANCE, event["alert_id"]])
group_tag = (
    "wazuh-group:v1:" + digest(identity)
    if groupable else None
)

received_ms = time.time_ns() // 1_000_000

alternatives = [
    {"_eq": {"_field": "sourceRef", "_value": source_ref}},
    {"_eq": {"_field": "tags", "_value": event_tag}},
]

if group_tag:
    alternatives.append({
        "_eq": {"_field": "tags", "_value": group_tag}
    })

query = {
    "query": [
        {"_name": "listAlert"},
        {
            "_name": "filter",
            "_and": [
                {"_eq": {"_field": "source", "_value": "wazuh"}},
                {"_eq": {"_field": "type", "_value": "wazuh"}},
                {"_or": alternatives},
            ],
        },
    ]
}

print(json.dumps({
    "groupable": groupable,
    "identity": identity,
    "source_ref": source_ref,
    "event_tag": event_tag,
    "group_tag": group_tag,
    "received_ms": received_ms,
    "cutoff_ms": received_ms - 600000,
    "query_body": json.dumps(query),
}))