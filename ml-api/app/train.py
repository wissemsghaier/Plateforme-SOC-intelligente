from __future__ import annotations

import argparse
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from app.features import FEATURE_COLUMNS

ALLOWED_LABELS = {"benign", "attaque_reseau", "malware", "active_directory"}


def train(input_path: Path, output_path: Path) -> dict[str, object]:
    frame = pd.read_csv(input_path)
    required = set(FEATURE_COLUMNS) | {"label"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"Colonnes obligatoires manquantes : {', '.join(missing)}")
    if frame.empty:
        raise ValueError("Le jeu de données ne contient aucune ligne.")
    if frame[FEATURE_COLUMNS].isnull().any().any():
        raise ValueError("Les colonnes de variables contiennent des valeurs vides.")

    labels = frame["label"].astype(str)
    unknown = sorted(set(labels) - ALLOWED_LABELS)
    if unknown:
        raise ValueError(f"Labels non autorisés : {', '.join(unknown)}")
    counts = labels.value_counts()
    too_small = sorted(label for label, count in counts.items() if count < 4)
    if len(counts) < 2 or too_small:
        raise ValueError("Il faut au moins deux classes et quatre exemples par classe.")
    if "benign" not in counts:
        raise ValueError("La classe benign est obligatoire pour entraîner le modèle d'anomalies.")

    encoder = LabelEncoder().fit(labels)
    encoded_labels = encoder.transform(labels)
    x_train, x_test, y_train, y_test = train_test_split(
        frame[FEATURE_COLUMNS],
        encoded_labels,
        test_size=0.25,
        random_state=42,
        stratify=encoded_labels,
    )
    random_forest = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1,
    )
    xgboost = XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        objective="multi:softprob",
        num_class=len(encoder.classes_),
        eval_metric="mlogloss",
        random_state=42,
        n_jobs=-1,
    )
    random_forest.fit(x_train, y_train)
    xgboost.fit(x_train, y_train)

    benign = frame.loc[labels == "benign", FEATURE_COLUMNS]
    anomaly_model = IsolationForest(
        n_estimators=300,
        contamination="auto",
        random_state=42,
    ).fit(benign)

    probabilities = (
        random_forest.predict_proba(x_test) + xgboost.predict_proba(x_test)
    ) / 2
    predictions = encoder.inverse_transform(probabilities.argmax(axis=1))
    expected = encoder.inverse_transform(y_test)
    report = classification_report(
        expected,
        predictions,
        labels=sorted(set(labels)),
        output_dict=True,
        zero_division=0,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "random_forest": random_forest,
            "xgboost": xgboost,
            "label_encoder": encoder,
            "anomaly_model": anomaly_model,
            "feature_columns": FEATURE_COLUMNS,
            "labels": sorted(set(labels)),
            "metrics": report,
        },
        output_path,
    )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Entraîne les modèles de l'API ML SOC.")
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=Path("/app/models/models.joblib"))
    args = parser.parse_args()
    report = train(args.input, args.output)
    print(f"Modèle enregistré dans : {args.output}")
    print(pd.DataFrame(report).transpose().round(3).to_string())


if __name__ == "__main__":
    main()
