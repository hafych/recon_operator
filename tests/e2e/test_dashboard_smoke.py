"""Browser smoke tests for the operator dashboard (Playwright).

Run only in the CI e2e job (or locally with browsers installed):

    RUN_E2E=1 python -m unittest discover -s tests/e2e -t . -v
"""

from __future__ import annotations

import os
import unittest

from .helpers import DashboardServer


@unittest.skipUnless(os.getenv("RUN_E2E") == "1", "Set RUN_E2E=1 to run Playwright smoke tests")
class DashboardPlaywrightSmokeTests(unittest.TestCase):
    server: DashboardServer | None = None

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError as exc:
            raise unittest.SkipTest(f"playwright not installed: {exc}") from exc

        cls.server = DashboardServer()
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server is not None:
            cls.server.stop()
            cls.server = None

    def test_dashboard_loads_with_accessible_controls_and_nonce_csp(self):
        from playwright.sync_api import sync_playwright

        assert self.server is not None
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            response = page.goto(self.server.base_url + "/", wait_until="networkidle")
            self.assertIsNotNone(response)
            assert response is not None
            self.assertEqual(response.status, 200)

            body = page.content()
            self.assertIn("Recon Operator", body)

            token = page.locator("#apiToken")
            self.assertTrue(token.count() >= 1)
            self.assertEqual(token.get_attribute("type"), "password")

            # Keyboard path: disclose connection controls, then focus the token.
            connection = page.locator(".connection-menu > summary")
            connection.focus()
            page.keyboard.press("Enter")
            self.assertTrue(page.locator(".connection-menu").evaluate("node => node.open"))
            token.focus()
            self.assertTrue(
                page.evaluate("document.activeElement && document.activeElement.id === 'apiToken'")
            )

            key_meta = page.locator("#keyMeta")
            self.assertTrue(key_meta.count() >= 1)

            csp = response.headers.get("content-security-policy", "")
            self.assertIn("nonce-", csp)
            self.assertNotIn("unsafe-inline", csp)

            page.fill("#apiToken", self.server.token)
            page.keyboard.press("Tab")
            whoami = page.evaluate(
                """async (token) => {
                    const res = await fetch('/auth/whoami', {
                        headers: { 'X-API-KEY': token }
                    });
                    return { status: res.status, body: await res.json() };
                }""",
                self.server.token,
            )
            self.assertEqual(whoami["status"], 200)
            self.assertIn("key_id", whoami["body"])
            self.assertIn("scopes", whoami["body"])

            live = page.evaluate(
                """async () => {
                    const res = await fetch('/live');
                    return { status: res.status, body: await res.json() };
                }"""
            )
            self.assertEqual(live["status"], 200)
            self.assertEqual(live["body"]["status"], "live")

            browser.close()

    def test_authorized_scan_flows_from_preset_to_encrypted_evidence(self):
        from playwright.sync_api import expect, sync_playwright

        assert self.server is not None
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 900})
            page.goto(self.server.base_url + "/", wait_until="networkidle")

            page.locator(".connection-menu > summary").click()
            page.fill("#apiToken", self.server.token)
            page.click("#connectBtn")
            expect(page.locator("#connectionLabel")).to_contain_text("Primary")

            page.select_option("#preset", "discovery")
            self.assertIn("Host discovery", page.locator("#presetMeta").inner_text())
            self.assertEqual(page.locator("#scanType").input_value(), "Ping")

            page.click("#scanBtn")
            expect(page.locator("#toast")).to_contain_text("Scan complete", timeout=30_000)

            self.assertEqual(page.locator("#hostMetric").inner_text(), "1")
            self.assertIn("Ping", page.locator("#resultTitle").inner_text())
            self.assertGreaterEqual(int(page.locator("#historyCount").inner_text()), 1)
            self.assertIn("encrypted", page.locator("#resultSource").inner_text().lower())

            browser.close()

    def test_api_values_render_as_text_not_markup(self):
        from playwright.sync_api import sync_playwright

        assert self.server is not None
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(self.server.base_url + "/", wait_until="networkidle")

            payload = "<img src=x onerror=window.__recon_xss=true>"
            page.evaluate(
                "target => renderJobs([{job_id:'safe-dom', target, status:'completed'}])",
                payload,
            )

            self.assertIn(payload, page.locator("#jobs").inner_text())
            self.assertEqual(page.locator("#jobs img").count(), 0)
            self.assertIsNone(page.evaluate("window.__recon_xss"))
            browser.close()


if __name__ == "__main__":
    unittest.main()
