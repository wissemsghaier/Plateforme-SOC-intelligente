import json
import requests

obs = json.loads(r"""$extract_observables.message""")
values = obs["ip_list"] + obs["hash_list"] + obs["domain_list"] + obs["url_list"]

result = {"status": "skipped", "misp_hits": 0, "event_ids": [], "tags": [], "matched": []}

if values:
    try:
        r = requests.post(
            "$misp_url".rstrip("/") + "/attributes/restSearch",
            headers={
                "Authorization": "$misp_api_key",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            json={"returnFormat": "json", "value": values,
                  "includeEventTags": True, "limit": 100},
            timeout=15,
            verify=False,  # lab : certificat auto-signé
        )
        r.raise_for_status()
        attributes = (r.json().get("response") or {}).get("Attribute") or []

        for attr in attributes:
            if attr.get("event_id") not in result["event_ids"]:
                result["event_ids"].append(attr.get("event_id"))
            if attr.get("value") not in result["matched"]:
                result["matched"].append(attr.get("value"))
            for tag in attr.get("Tag") or []:
                if tag.get("name") not in result["tags"]:
                    result["tags"].append(tag.get("name"))

        result["misp_hits"] = len(attributes)
        result["status"] = "ok"
    except Exception as e:
        result["status"] = "error"
        result["error"] = type(e).__name__

print(json.dumps(result))