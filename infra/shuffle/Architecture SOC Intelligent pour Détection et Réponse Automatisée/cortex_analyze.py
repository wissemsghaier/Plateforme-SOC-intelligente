import ipaddress
import json
import re

import requests


CORTEX = "$cortex_url".rstrip("/")
HEADERS = {
    "Authorization": "Bearer $cortex_api_key",
    "Accept": "application/json",
}
WANTED = {
    "VirusTotal": "VirusTotal_GetReport",
    "AbuseIPDB": "AbuseIPDB",
    "MISP": "MISP_",
}
SERVICE_SCOPE = {
    "VirusTotal": "public",
    "AbuseIPDB": "public",
    "MISP": "any",
}

result = {
    "status": "skipped",
    "vt_malicious": 0,
    "verdicts": [],
    "analyzers": [],
    "errors": 0,
    "error_details": [],
}


def add_error(service, message):
    result["errors"] += 1
    result["error_details"].append(
        {
            "service": service,
            "message": message,
        }
    )


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


def unwrap_node(node):
    data = to_obj(node)
    if not data:
        return {}
    msg = to_obj(data.get("message"))
    return msg if msg else data


def get_observables(input_data):
    candidates = (
        input_data.get("extract_observables"),
        input_data.get("$extract_observables"),
        input_data.get("EXTRACT_OBSERVABLES"),
    )
    for node in candidates:
        parsed = unwrap_node(node or {})
        if parsed:
            return parsed

    parsed_template = to_obj(r"""$extract_observables.message""")
    if parsed_template:
        return parsed_template

    parsed_template_raw = to_obj(r"""$extract_observables""")
    if parsed_template_raw:
        parsed = unwrap_node(parsed_template_raw)
        if parsed:
            return parsed

    return {}


def request_json(method, path, timeout=10, **kwargs):
    response = requests.request(
        method,
        f"{CORTEX}{path}",
        headers=HEADERS,
        timeout=timeout,
        **kwargs,
    )
    response.raise_for_status()
    return response.json()


def add_ip(value, seen, public_ips, private_ips):
    try:
        address = ipaddress.ip_address(value)
    except (TypeError, ValueError):
        add_error("input", f"Adresse IP invalide : {value}")
        return

    ip = str(address)
    if ip in seen:
        return
    seen.add(ip)

    if address.is_global:
        public_ips.append(ip)
    else:
        private_ips.append(ip)


def normalize_ips(observables):
    public_ips = []
    private_ips = []
    seen = set()

    for raw_list in (
        observables.get("public_ips", []),
        observables.get("private_ips", []),
        observables.get("ips", []),
        observables.get("ip_list", []),
    ):
        if isinstance(raw_list, list):
            for value in raw_list:
                add_ip(value, seen, public_ips, private_ips)

    add_ip(observables.get("src_ip"), seen, public_ips, private_ips)
    add_ip(observables.get("dst_ip"), seen, public_ips, private_ips)

    return public_ips, private_ips


def choose_ip_for_service(service, public_ips, private_ips):
    scope = SERVICE_SCOPE.get(service, "any")
    if scope == "public":
        return public_ips[0] if public_ips else ""
    if public_ips:
        return public_ips[0]
    return private_ips[0] if private_ips else ""


incoming = globals().get("inputData")
if incoming is None:
    incoming = globals().get("data")
if incoming is None:
    incoming = globals().get("params")
if incoming is None or not isinstance(incoming, dict):
    incoming = {}

obs = get_observables(incoming)

public_ips, private_ips = normalize_ips(obs)
result["ip_scope"] = {
    "public_count": len(public_ips),
    "private_count": len(private_ips),
}
result["debug_obs_keys"] = list(obs.keys()) if isinstance(obs, dict) else []

if not public_ips and not private_ips:
    result["reason"] = "Aucune IP valide à analyser."
    result["status"] = "error" if result["errors"] else "skipped"
else:
    selected = []

    try:
        available = request_json(
            "GET",
            "/api/analyzer/type/ip",
        )

        if not isinstance(available, list):
            raise ValueError("Liste des analyseurs Cortex invalide.")

        for service, prefix in WANTED.items():
            candidates = [
                analyzer
                for analyzer in available
                if isinstance(analyzer, dict)
                and analyzer.get("name", "").startswith(prefix)
                and analyzer.get("id")
            ]

            if not candidates:
                add_error(
                    service,
                    "Analyseur absent ou non activé pour le type ip.",
                )
                continue

            chosen_ip = choose_ip_for_service(service, public_ips, private_ips)
            if not chosen_ip:
                result["analyzers"].append(
                    {
                        "service": service,
                        "analyzer": candidates[0]["name"],
                        "ip": "",
                        "status": "skipped",
                        "reason": "no_eligible_ip",
                    }
                )
                continue

            selected.append((service, candidates[0], chosen_ip))

    except (requests.RequestException, ValueError) as exc:
        add_error("Cortex", str(exc))

    completed = 0

    for service, analyzer, ip in selected:
        entry = {
            "service": service,
            "analyzer": analyzer["name"],
            "ip": ip,
            "status": "error",
        }
        result["analyzers"].append(entry)

        try:
            job = request_json(
                "POST",
                f"/api/analyzer/{analyzer['id']}/run",
                json={
                    "data": ip,
                    "dataType": "ip",
                    "tlp": 2,
                },
            )

            if not isinstance(job, dict) or not job.get("id"):
                raise ValueError("Réponse de création du job invalide.")

            entry["job_id"] = job["id"]

            report = request_json(
                "GET",
                f"/api/job/{job['id']}/waitreport",
                timeout=25,
                params={"atMost": "20second"},
            )

            if not isinstance(report, dict):
                raise ValueError("Rapport Cortex invalide.")

            entry["status"] = report.get("status", "Unknown")

            if entry["status"] != "Success":
                raise ValueError(
                    f"Job {job['id']} : état {entry['status']}. "
                    "Consultez ce job dans Cortex ; il peut être "
                    "encore en cours ou avoir échoué."
                )

            report_body = report.get("report") or {}
            summary = report_body.get("summary") or {}
            taxonomies = summary.get("taxonomies") or []

            if not isinstance(taxonomies, list):
                raise ValueError("Taxonomies Cortex invalides.")

            entry["summary"] = summary

            for taxonomy in taxonomies:
                level = taxonomy.get("level")
                value = str(taxonomy.get("value", ""))

                result["verdicts"].append(
                    {
                        "service": service,
                        "analyzer": analyzer["name"],
                        "ip": ip,
                        "namespace": taxonomy.get("namespace"),
                        "predicate": taxonomy.get("predicate"),
                        "level": level,
                        "value": value,
                    }
                )

                if service == "VirusTotal" and level == "malicious":
                    match = re.match(r"(\d+)\s*/", value)
                    count = int(match.group(1)) if match else 1
                    result["vt_malicious"] = max(
                        result["vt_malicious"],
                        count,
                    )

            completed += 1

        except (requests.RequestException, ValueError) as exc:
            entry["error"] = str(exc)
            add_error(service, str(exc))

    if completed and result["errors"] == 0:
        result["status"] = "ok"
    elif completed:
        result["status"] = "partial"
    else:
        result["status"] = "error"

print(json.dumps(result, ensure_ascii=False))
