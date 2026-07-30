import unittest
from unittest.mock import AsyncMock

from grafana import GrafanaClient, GrafanaError


class RenderPanelByRefTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = GrafanaClient("http://grafana.invalid", "token")
        self.dashboard = {
            "uid": "fleet-overview",
            "title": "Fleet Overview",
            "slug": "fleet-overview",
            "panels": [
                {"id": 7, "title": "Estado de nodos", "type": "table"},
            ],
        }
        self.client.find_dashboards = AsyncMock(return_value=[
            {"uid": "fleet-overview", "title": "Fleet Overview"},
        ])
        self.client.get_dashboard = AsyncMock(return_value=self.dashboard)
        self.client.render_panel = AsyncMock(return_value=b"png")

    async def test_resolves_and_renders_unique_panel(self):
        result = await self.client.render_panel_by_ref(
            "fleet-overview",
            "Estado de nodos",
            "now-15m",
            "now",
            1200,
            700,
            "dark",
            "browser",
        )

        self.assertEqual(
            result,
            (self.dashboard, self.dashboard["panels"][0], b"png"),
        )
        self.client.render_panel.assert_awaited_once_with(
            "fleet-overview",
            "fleet-overview",
            7,
            "now-15m",
            "now",
            1200,
            700,
            "dark",
            "browser",
            None,
        )

    async def test_missing_dashboard_is_an_operational_error(self):
        self.client.find_dashboards.return_value = []

        with self.assertRaisesRegex(GrafanaError, "no encontre el dashboard"):
            await self.client.render_panel_by_ref(
                "missing", "Estado de nodos"
            )

    async def test_ambiguous_panel_is_rejected(self):
        self.dashboard["panels"].append(
            {"id": 8, "title": "Estado de nodos secundario", "type": "table"}
        )

        with self.assertRaisesRegex(GrafanaError, "es ambiguo"):
            await self.client.render_panel_by_ref(
                "fleet-overview", "Estado"
            )


if __name__ == "__main__":
    unittest.main()
