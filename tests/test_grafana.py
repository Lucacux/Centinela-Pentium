import unittest
from unittest.mock import AsyncMock, patch

from grafana import GrafanaClient, GrafanaError, png_size


def png(width=10, height=10):
    return (
        b"\x89PNG\r\n\x1a\n"
        + b"\x00\x00\x00\x0dIHDR"
        + width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + b"\x08\x02\x00\x00\x00"
    )


class FakeResponse:
    def __init__(self, status, body=b"", content_type="text/plain"):
        self.status = status
        self.body = body
        self.headers = {"Content-Type": content_type}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def read(self):
        return self.body


class FakeSession:
    def __init__(self, responses):
        self.responses = responses
        self.requests = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    def get(self, *_args, **_kwargs):
        self.requests += 1
        return self.responses.pop(0)


class RenderRetryTests(unittest.IsolatedAsyncioTestCase):
    async def test_retries_transient_renderer_failure(self):
        image = png(1600, 1600)
        session = FakeSession([
            FakeResponse(500),
            FakeResponse(200, image, "image/png"),
        ])
        sleep = AsyncMock()
        client = GrafanaClient("http://grafana.invalid", "token")

        with patch("grafana.aiohttp.ClientSession", return_value=session), patch(
            "grafana.asyncio.sleep", sleep
        ):
            result = await client._get_bytes("/render/d/fleet/fleet")

        self.assertEqual(png_size(result), (1600, 1600))
        self.assertEqual(session.requests, 2)
        sleep.assert_awaited_once_with(10)

    def test_default_timeout_covers_grafana_render_deadline(self):
        client = GrafanaClient("http://grafana.invalid", "token")

        self.assertEqual(client._timeout.total, 70)

    async def test_does_not_retry_non_transient_http_error(self):
        session = FakeSession([FakeResponse(401)])
        sleep = AsyncMock()
        client = GrafanaClient("http://grafana.invalid", "token")

        with patch("grafana.aiohttp.ClientSession", return_value=session), patch(
            "grafana.asyncio.sleep", sleep
        ):
            with self.assertRaisesRegex(GrafanaError, "HTTP 401"):
                await client._get_bytes("/render/d/fleet/fleet")

        self.assertEqual(session.requests, 1)
        sleep.assert_not_awaited()


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
