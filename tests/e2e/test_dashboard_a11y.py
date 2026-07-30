"""axe-core accessibility regression for the operator dashboard.

RUN_E2E=1 python -m unittest discover -s tests/e2e -t . -v
"""

from __future__ import annotations

import os
import unittest

from .helpers import DashboardServer


def _serious_violations(results) -> list[dict]:
    """Return axe violations with serious/critical impact."""
    violations = results.response.get("violations") or []
    serious = []
    for item in violations:
        impact = (item.get("impact") or "").lower()
        if impact in {"serious", "critical"}:
            serious.append(item)
    return serious


def _format_violations(violations: list[dict]) -> str:
    lines = []
    for item in violations:
        nodes = item.get("nodes") or []
        targets = []
        for node in nodes[:5]:
            targets.extend(node.get("target") or [])
        lines.append(
            f"- {item.get('id')} ({item.get('impact')}): {item.get('help')} "
            f"[{', '.join(targets) or 'no targets'}]"
        )
    return "\n".join(lines)


@unittest.skipUnless(os.getenv("RUN_E2E") == "1", "Set RUN_E2E=1 to run Playwright a11y tests")
class DashboardAxeAccessibilityTests(unittest.TestCase):
    server: DashboardServer | None = None

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from axe_playwright_python.sync_playwright import Axe  # noqa: F401
            from playwright.sync_api import sync_playwright  # noqa: F401
        except ImportError as exc:
            raise unittest.SkipTest(f"playwright/axe not installed: {exc}") from exc

        cls.server = DashboardServer()
        cls.server.start()

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.server is not None:
            cls.server.stop()
            cls.server = None

    def test_dashboard_has_no_serious_axe_violations(self):
        from axe_playwright_python.sync_playwright import Axe
        from playwright.sync_api import sync_playwright

        assert self.server is not None
        options = {
            "runOnly": {
                "type": "tag",
                "values": ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
            },
            "resultTypes": ["violations"],
        }

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            response = page.goto(self.server.base_url + "/", wait_until="networkidle")
            self.assertIsNotNone(response)
            assert response is not None
            self.assertEqual(response.status, 200)

            results = Axe().run(page, options=options)
            serious = _serious_violations(results)
            self.assertEqual(
                serious,
                [],
                "Serious/critical axe-core violations:\n" + _format_violations(serious),
            )
            browser.close()

    def test_keyboard_and_aria_structure(self):
        from playwright.sync_api import sync_playwright

        assert self.server is not None
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_viewport_size({"width": 1280, "height": 900})
            page.goto(self.server.base_url + "/", wait_until="networkidle")

            # Landmark / live region semantics used by the operator UI.
            self.assertGreaterEqual(page.locator('[role="status"]').count(), 1)
            self.assertGreaterEqual(page.locator('[role="tablist"]').count(), 1)
            tabs = page.locator('[role="tab"]')
            self.assertGreaterEqual(tabs.count(), 4)
            self.assertEqual(page.locator('[role="tab"][aria-selected="true"]').count(), 1)

            # Keyboard: Tab reaches primary controls; Enter activates a tab.
            page.locator("#apiToken").focus()
            page.keyboard.press("Tab")
            # Walk a few tabs to ensure no focus trap on the control panel.
            for _ in range(8):
                page.keyboard.press("Tab")
            active_tag = page.evaluate(
                "document.activeElement ? document.activeElement.tagName : ''"
            )
            self.assertIn(active_tag, {"INPUT", "BUTTON", "SELECT", "TEXTAREA", "A"})

            # Switch result view via keyboard-activated tab button.
            json_tab = page.locator('[role="tab"][data-view="json"]')
            json_tab.focus()
            page.keyboard.press("Enter")
            self.assertEqual(json_tab.get_attribute("aria-selected"), "true")

            # Narrow viewport regression: no horizontal overflow at 320px.
            page.set_viewport_size({"width": 320, "height": 720})
            page.wait_for_timeout(100)
            overflow = page.evaluate(
                "() => ({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth })"
            )
            self.assertLessEqual(
                overflow["sw"],
                overflow["cw"] + 1,
                f"horizontal overflow at 320px: scrollWidth={overflow['sw']} clientWidth={overflow['cw']}",
            )

            browser.close()


if __name__ == "__main__":
    unittest.main()
