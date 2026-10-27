from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

from app.features import FEATURE_COLUMNS, alert_features
from app.train import ALLOWED_LABELS


def prepare_dataset(alerts_path: Path, labels_path: Path, output_path: Path) -> int:
    labels: dict[str, str] = {}
    with labels_path.open(newline="", encoding="utf-8-sig") as stream:
        for row in csv.DictReader(stream):
            alert_id = (row.get("alert_id") or "").strip()
            label = (row.get("label") or "").strip()
            if not alert_id:
                raise ValueError("Chaque ligne de labels.csv doit contenir alert_id.")
            if label not in ALLOWED_LABELS:
                raise ValueError(f"Label invalide pour {alert_id!r} : {label!r}")
            if alert_id in labels:
                raise ValueError(f"Identifiant dupliqué dans labels.csv : {alert_id}")
            labels[alert_id] = label

    rows: list[dict[str, object]] = []
    seen_ids: set[str] = set()
    with alerts_path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSON invalide à la ligne {line_number}.") from exc
            alert_id = record.get("alert_id")
            alert = record.get("alert")
            if not isinstance(alert_id, str) or not isinstance(alert, dict):
                raise ValueError(f"Structure d'alerte invalide à la ligne {line_number}.")
            if alert_id in seen_ids:
                raise ValueError(f"Identifiant d'alerte dupliqué : {alert_id}")
            seen_ids.add(alert_id)
            label = labels.get(alert_id)
            if label:
                rows.append({**alert_features(alert), "label": label})

    unmatched_labels = set(labels) - seen_ids
    if unmatched_labels:
        raise ValueError(f"{len(unmatched_labels)} identifiant(s) de labels absent(s) de l'export.")
    if not rows:
        raise ValueError("Aucune alerte étiquetée ne correspond à l'export.")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=[*FEATURE_COLUMNS, "label"])
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Construit le CSV de variables à partir des labels.")
    parser.add_argument("--alerts", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    count = prepare_dataset(args.alerts, args.labels, args.output)
    print(f"{count} alertes étiquetées enregistrées dans {args.output}")


if __name__ == "__main__":
    main()
