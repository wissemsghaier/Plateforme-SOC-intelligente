from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any

import requests
from requests.auth import HTTPBasicAuth


def export_alerts(hours: int, output_path: Path) -> int:
    base_url = os.getenv("WAZUH_INDEXER_URL", "").rstrip("/")
    username = os.getenv("WAZUH_INDEXER_USER", "")
    password = os.getenv("WAZUH_INDEXER_PASS", "")
    index = os.getenv("WAZUH_INDEXER_INDEX", "wazuh-alerts-*")
    ca_cert = os.getenv("WAZUH_INDEXER_CA_CERT", "")
    if not base_url or not username or not password:
        raise ValueError("WAZUH_INDEXER_URL, WAZUH_INDEXER_USER et WAZUH_INDEXER_PASS sont requis.")
    if os.getenv("WAZUH_INDEXER_VERIFY_TLS", "true").lower() != "true":
        raise ValueError("La vérification TLS ne peut pas être désactivée.")

    query: dict[str, Any] = {
        "size": 10000,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {"range": {"timestamp": {"gte": f"now-{hours}h"}}},
        "_source": True,
    }
    response = requests.post(
        f"{base_url}/{index}/_search",
        auth=HTTPBasicAuth(username, password),
        json=query,
        timeout=60,
        verify=ca_cert or True,
    )
    response.raise_for_status()
    result = response.json()
    hits = result.get("hits", {}).get("hits")
    if not isinstance(hits, list):
        raise ValueError("La réponse de l'indexer ne contient pas la liste hits attendue.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as stream:
        for hit in hits:
            source = hit.get("_source")
            alert_id = hit.get("_id")
            if isinstance(source, dict) and isinstance(alert_id, str):
                stream.write(
                    json.dumps(
                        {"alert_id": alert_id, "alert": source},
                        ensure_ascii=False,
                    )
                    + "\n"
                )
    return len(hits)


def main() -> None:
    parser = argparse.ArgumentParser(description="Export limité d'alertes depuis Wazuh Indexer.")
    parser.add_argument("--hours", type=int, choices=range(1, 169), default=24)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    count = export_alerts(args.hours, args.output)
    print(f"{count} alertes exportées vers {args.output}")


if __name__ == "__main__":
    main()
