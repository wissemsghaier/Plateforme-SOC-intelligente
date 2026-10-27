from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import shap
from fastapi import FastAPI, Header, HTTPException
from hdbscan import HDBSCAN
from pydantic import BaseModel, Field
from sklearn.preprocessing import StandardScaler

from app.features import FEATURE_COLUMNS, feature_frame

MODEL_PATH = Path(os.getenv("MODEL_PATH", "/app/models/models.joblib"))
TOKEN = os.getenv("ML_API_TOKEN", "")
HOST_CRITICALITY = {"windows-cible": 1.2, "ubuntu-cible": 1.0}
app = FastAPI(title="API ML SOC", version="1.0.0")


class AnalyzeRequest(BaseModel):
    alert: dict[str, Any]
    enrichment: dict[str, Any] = Field(default_factory=dict)


class ClusterRequest(BaseModel):
    alerts: list[dict[str, Any]] = Field(min_length=2, max_length=500)


def _authorize(token: str | None) -> None:
    if not TOKEN or TOKEN.startswith("CHANGE_ME") or len(TOKEN) < 32:
        raise HTTPException(status_code=503, detail="ML_API_TOKEN doit être un secret aléatoire d'au moins 32 caractères.")
    if token is None or not hmac.compare_digest(token, TOKEN):
        raise HTTPException(status_code=401, detail="Token API invalide.")


def _load_models() -> dict[str, Any]:
    if not MODEL_PATH.is_file():
        raise HTTPException(status_code=503, detail="Aucun modèle entraîné n'est disponible.")
    try:
        models = joblib.load(MODEL_PATH)
    except (OSError, ValueError, EOFError) as exc:
        raise HTTPException(status_code=503, detail="Impossible de charger le modèle ML.") from exc
    if models.get("feature_columns") != FEATURE_COLUMNS:
        raise HTTPException(status_code=503, detail="Les variables du modèle ne correspondent pas à l'API.")
    return models


def _analyze(alert: dict[str, Any], enrichment: dict[str, Any]) -> dict[str, Any]:
    models = _load_models()
    frame = feature_frame([alert], [enrichment])
    random_forest = models["random_forest"]
    xgboost = models["xgboost"]
    probabilities = (
        random_forest.predict_proba(frame)[0] + xgboost.predict_proba(frame)[0]
    ) / 2
    index = int(np.argmax(probabilities))
    category = str(models["label_encoder"].classes_[index])
    confidence = float(probabilities[index])
    level = float(frame.iloc[0]["rule_level"])
    host = str((alert.get("agent") or {}).get("name", ""))

    if category == "benign":
        risk_score = 0.0
    else:
        base = confidence * 70 + min(level, 15) * 2
        base += 10 * float(frame.iloc[0]["misp_hits"])
        risk_score = min(100.0, base * HOST_CRITICALITY.get(host, 1.0))

    explainer = shap.TreeExplainer(random_forest)
    raw_values = explainer.shap_values(frame)
    if isinstance(raw_values, list):
        impacts = np.asarray(raw_values[index])[0]
    else:
        values = np.asarray(raw_values)
        if values.ndim == 3:
            impacts = values[0, :, index]
        elif values.ndim == 2:
            impacts = values[0]
        else:
            raise ValueError(f"Format SHAP inattendu : {values.shape}")

    explanations = sorted(
        (
            {"feature": name, "impact": round(float(value), 4)}
            for name, value in zip(FEATURE_COLUMNS, impacts)
        ),
        key=lambda row: abs(row["impact"]),
        reverse=True,
    )[:4]
    anomaly_model = models["anomaly_model"]
    anomaly_score = float(-anomaly_model.score_samples(frame)[0])
    anomaly_label = int(anomaly_model.predict(frame)[0])
    suggestions = {
        "attaque_reseau": "Vérifier l'IP source et les règles réseau ; proposer un blocage à l'analyste.",
        "malware": "Vérifier le hash, isoler le fichier dans le laboratoire et confirmer avec l'analyste.",
        "active_directory": "Vérifier l'identité et les événements d'authentification avant toute action.",
        "benign": "Aucune contre-mesure automatique recommandée.",
    }
    return {
        "category": category,
        "confidence": round(confidence, 4),
        "risk_score": round(risk_score, 1),
        "explanation": explanations,
        "zero_day_suspect": anomaly_label == -1,
        "anomaly_score": round(anomaly_score, 4),
        "countermeasure": suggestions.get(category, "Faire examiner l'alerte par un analyste."),
        "model_metrics": models.get("metrics"),
    }


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "model_loaded": MODEL_PATH.is_file(),
        "token_configured": bool(TOKEN) and not TOKEN.startswith("CHANGE_ME") and len(TOKEN) >= 32,
    }


@app.post("/analyze")
def analyze(
    request: AnalyzeRequest,
    x_api_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _authorize(x_api_token)
    return _analyze(request.alert, request.enrichment)


@app.post("/cluster")
def cluster(
    request: ClusterRequest,
    x_api_token: str | None = Header(default=None),
) -> dict[str, Any]:
    _authorize(x_api_token)
    frame = feature_frame(request.alerts)
    scaled = StandardScaler().fit_transform(frame)
    labels = HDBSCAN(min_cluster_size=2, min_samples=1).fit_predict(scaled)
    return {"clusters": [int(label) for label in labels], "noise_label": -1}
