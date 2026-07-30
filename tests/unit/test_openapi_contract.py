"""OpenAPI contract checks: schema shape and route parity with the Quart app."""

from __future__ import annotations

import os
import re
import unittest

os.environ.setdefault("API_AUTH_REQUIRED", "true")
os.environ.setdefault("API_AUTH_TOKEN", "test-token")
os.environ.setdefault("FERNET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
os.environ.setdefault("SCAN_LOG_PATH", "/tmp/nmap-automator-openapi.log")
os.environ.setdefault("TELEGRAM_BOT_TOKEN", "")
os.environ.setdefault("TELEGRAM_CHAT_ID", "")
os.environ.setdefault("STATE_DB_PATH", "/tmp/recon-operator-openapi.db")

import autonmap


def _normalize_rule(path: str) -> str:
    """Convert Quart/Werkzeug rule to OpenAPI-style path template."""
    # <path:task_id> or <job_id> -> {task_id} / {job_id}
    return re.sub(r"<(?:path:)?([^>]+)>", r"{\1}", path)


def _app_http_routes() -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for rule in autonmap.app.url_map.iter_rules():
        if rule.endpoint == "static":
            continue
        path = _normalize_rule(rule.rule)
        for method in sorted(rule.methods or []):
            if method in {"HEAD", "OPTIONS"}:
                continue
            routes.add((method.upper(), path))
    return routes


def _openapi_http_routes(spec: dict) -> set[tuple[str, str]]:
    routes: set[tuple[str, str]] = set()
    for path, item in (spec.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        for method, operation in item.items():
            if method.startswith("x-") or not isinstance(operation, dict):
                continue
            if method.lower() not in {
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "options",
                "head",
            }:
                continue
            routes.add((method.upper(), path))
    return routes


class OpenApiContractTests(unittest.IsolatedAsyncioTestCase):
    def test_openapi_document_has_required_top_level_shape(self):
        spec = autonmap.build_openapi_spec()
        self.assertEqual(spec["openapi"], "3.0.3")
        self.assertIn("info", spec)
        self.assertEqual(spec["info"]["version"], autonmap.VERSION)
        self.assertIn("paths", spec)
        self.assertIn("components", spec)
        self.assertIn("securitySchemes", spec["components"])
        auth = spec["components"]["securitySchemes"]["ApiKeyAuth"]
        self.assertEqual(auth["type"], "apiKey")
        self.assertEqual(auth["in"], "header")
        self.assertEqual(auth["name"], autonmap.API_AUTH_HEADER)

    def test_critical_paths_exist_with_expected_methods(self):
        spec = autonmap.build_openapi_spec()
        paths = spec["paths"]
        expected = {
            "/live": {"get"},
            "/ready": {"get"},
            "/health": {"get"},
            "/openapi.json": {"get"},
            "/scan": {"post"},
            "/jobs": {"get"},
            "/jobs/{job_id}": {"get", "delete"},
            "/schedule": {"post"},
            "/tasks": {"get"},
            "/tasks/{task_id}": {"delete"},
            "/results": {"get"},
            "/results/{result_id}": {"get"},
            "/results/import": {"post"},
            "/results/diff": {"post"},
            "/tools": {"get"},
            "/tools/ai-context": {"get"},
            "/recon/plan": {"post"},
            "/auth/whoami": {"get"},
            "/": {"get"},
            "/ui": {"get"},
        }
        for path, methods in expected.items():
            self.assertIn(path, paths, f"missing path {path}")
            for method in methods:
                self.assertIn(method, paths[path], f"missing {method.upper()} {path}")
                op = paths[path][method]
                self.assertIn("responses", op)
                self.assertTrue(op["responses"], f"no responses for {method} {path}")

    def test_openapi_routes_match_registered_app_routes(self):
        """Every documented OpenAPI operation must exist on the live Quart app."""
        spec = autonmap.build_openapi_spec()
        openapi_routes = _openapi_http_routes(spec)
        app_routes = _app_http_routes()
        missing_in_app = sorted(openapi_routes - app_routes)
        self.assertEqual(
            missing_in_app,
            [],
            f"OpenAPI documents routes not registered on the app: {missing_in_app}",
        )

    def test_authenticated_app_routes_are_documented(self):
        """Core authenticated API surfaces should appear in OpenAPI."""
        spec = autonmap.build_openapi_spec()
        openapi_routes = _openapi_http_routes(spec)
        required = {
            ("POST", "/scan"),
            ("GET", "/jobs"),
            ("GET", "/jobs/{job_id}"),
            ("DELETE", "/jobs/{job_id}"),
            ("POST", "/schedule"),
            ("GET", "/tasks"),
            ("DELETE", "/tasks/{task_id}"),
            ("GET", "/results"),
            ("GET", "/results/{result_id}"),
            ("POST", "/results/import"),
            ("POST", "/results/diff"),
            ("GET", "/tools"),
            ("GET", "/tools/ai-context"),
            ("POST", "/recon/plan"),
            ("GET", "/auth/whoami"),
            ("GET", "/live"),
            ("GET", "/ready"),
            ("GET", "/health"),
            ("GET", "/openapi.json"),
        }
        missing = sorted(required - openapi_routes)
        self.assertEqual(missing, [], f"Required API routes missing from OpenAPI: {missing}")

    async def test_openapi_json_endpoint_matches_builder(self):
        client = autonmap.app.test_client()
        response = await client.get("/openapi.json")
        payload = await response.get_json()
        self.assertEqual(response.status_code, 200)
        built = autonmap.build_openapi_spec()
        self.assertEqual(payload["openapi"], built["openapi"])
        self.assertEqual(set(payload["paths"]), set(built["paths"]))
        self.assertEqual(payload["info"]["version"], autonmap.VERSION)

    async def test_scan_request_schema_lists_supported_types(self):
        spec = autonmap.build_openapi_spec()
        scan_schema = spec["components"]["schemas"]["ScanRequest"]
        enum_values = scan_schema["properties"]["scan_type"]["enum"]
        for name in autonmap.SUPPORTED_SCAN_TYPES:
            self.assertIn(name, enum_values)


if __name__ == "__main__":
    unittest.main()
