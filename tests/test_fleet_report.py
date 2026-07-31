from io import BytesIO
import unittest
from unittest.mock import AsyncMock

from PIL import Image

from fleet_report import render_fleet_pages, split_png_vertical


def png(width, height):
    output = BytesIO()
    Image.new("RGB", (width, height), "#111217").save(output, "PNG")
    return output.getvalue()


class SplitPngTests(unittest.TestCase):
    def test_small_image_stays_byte_identical(self):
        source = png(200, 300)
        self.assertEqual(split_png_vertical(source, 500), [source])

    def test_tall_image_is_split_without_losing_rows(self):
        pages = split_png_vertical(png(200, 1201), 500)
        self.assertEqual(len(pages), 3)
        heights = []
        for page in pages:
            with Image.open(BytesIO(page)) as image:
                heights.append(image.height)
        self.assertEqual(heights, [500, 500, 201])


class RenderFleetPagesTests(unittest.IsolatedAsyncioTestCase):
    async def test_resolves_dashboard_once_and_paginates(self):
        client = AsyncMock()
        client.find_dashboards.return_value = [{"uid": "fleet-overview"}]
        client.get_dashboard.return_value = {
            "uid": "fleet-overview",
            "slug": "fleet-overview",
            "title": "Fleet Overview",
        }
        client.render_dashboard.return_value = png(100, 900)

        dashboard, pages = await render_fleet_pages(
            client, "fleet-overview", "now-6h", "now",
            1600, 2200, 500, "dark", "browser",
        )

        self.assertEqual(dashboard["title"], "Fleet Overview")
        self.assertEqual(len(pages), 2)
        client.render_dashboard.assert_awaited_once_with(
            "fleet-overview", "fleet-overview", "now-6h", "now",
            1600, 2200, "dark", "browser",
        )


if __name__ == "__main__":
    unittest.main()
