from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ml-api"))

from app.features import alert_features  # noqa: E402

response_spec = importlib.util.spec_from_file_location(
    "response_service", ROOT / "response-api" / "app.py"
)
if response_spec is None or response_spec.loader is None:
    raise RuntimeError("Impossible de charger le module de réponse.")
response_app = importlib.util.module_from_spec(response_spec)
sys.modules[response_spec.name] = response_app
response_spec.loader.exec_module(response_app)

copilot_spec = importlib.util.spec_from_file_location(
    "copilot_service", ROOT / "copilot-api" / "app.py"
)
if copilot_spec is None or copilot_spec.loader is None:
    raise RuntimeError("Impossible de charger le module Copilot.")
copilot_app = importlib.util.module_from_spec(copilot_spec)
sys.modules[copilot_spec.name] = copilot_app
copilot_spec.loader.exec_module(copilot_app)


class FeatureTests(unittest.TestCase):
    def test_alert_feature_extraction_is_bounded(self) -> None:
        result = alert_features(
            {
                "timestamp": "2026-10-19T23:30:00Z",
                "rule": {"level": 18, "firedtimes": 2000},
                "agent": {"name": "windows-cible"},
                "data": {"srcip": "10.10.10.20"},
            },
            {"vt_malicious": 800, "misp_hits": -1},
        )
        self.assertEqual(result["rule_level"], 15.0)
        self.assertEqual(result["rule_firedtimes"], 1000.0)
        self.assertEqual(result["is_off_hours"], 1.0)
        self.assertEqual(result["agent_is_windows"], 1.0)
        self.assertEqual(result["vt_malicious"], 100.0)
        self.assertEqual(result["misp_hits"], 0.0)


class ResponseApiTests(unittest.TestCase):
    def test_script_escapes_parameter_and_whitelists_action(self) -> None:
        with patch.dict(os.environ, {"WINRM_ALLOWED_USERS": "user.name"}):
            script = response_app._build_script("disable_user", "user.name")
        self.assertIn("Disable-LocalUser", script)
        from fastapi import HTTPException

        with self.assertRaises(HTTPException):
            response_app._build_script("run_command", "anything")

    def test_response_requires_action_parameter_allowlist(self) -> None:
        from fastapi import HTTPException

        with patch.dict(os.environ, {"WINRM_ALLOWED_USERS": "testsoc"}):
            with self.assertRaises(HTTPException) as raised:
                response_app._build_script("disable_user", "Administrator")
        self.assertEqual(raised.exception.status_code, 403)

    def test_response_rejects_host_not_in_allowlist(self) -> None:
        request = response_app.RespondRequest(
            host="192.168.56.41",
            action="disable_user",
            param="testsoc",
            approved_by="analyste",
        )
        from fastapi import HTTPException

        test_token = "a" * 40
        with patch.object(response_app, "TOKEN", test_token), patch.object(
            response_app, "ALLOWED_HOSTS", {"192.168.56.40"}
        ):
            with self.assertRaises(HTTPException) as raised:
                response_app.respond(request, x_api_token=test_token)
        self.assertEqual(raised.exception.status_code, 403)

    def test_response_rejects_injected_parameter(self) -> None:
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            response_app.RespondRequest(
                host="192.168.56.40",
                action="disable_user",
                param="user'; Remove-Item *",
                approved_by="analyste",
            )

    def test_response_refuses_unencrypted_winrm(self) -> None:
        from fastapi import HTTPException

        with patch.dict(os.environ, {"WINRM_ENABLED": "true", "WINRM_PORT": "5985"}):
            with self.assertRaises(HTTPException) as raised:
                response_app._run_winrm("192.168.56.40", "Get-Date")
        self.assertEqual(raised.exception.status_code, 503)


class CopilotApiTests(unittest.TestCase):
    def test_copilot_requires_token_before_querying_wazuh(self) -> None:
        from fastapi import HTTPException

        request = copilot_app.AskRequest(question="Résume les alertes.")
        with patch.object(copilot_app, "TOKEN", "a" * 40), patch.object(
            copilot_app, "_fetch_alerts", side_effect=AssertionError("Wazuh ne doit pas être appelé")
        ):
            with self.assertRaises(HTTPException) as raised:
                copilot_app.ask(request, x_api_token="incorrect")
        self.assertEqual(raised.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
