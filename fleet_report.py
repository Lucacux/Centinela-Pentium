"""Render and paginate the complete Grafana Fleet Overview for Discord."""

from io import BytesIO

from PIL import Image

from grafana import GrafanaError


def split_png_vertical(data, page_height):
    """Split a tall PNG into lossless, readable Discord pages."""
    if page_height <= 0:
        return [data]
    with Image.open(BytesIO(data)) as image:
        image.load()
        if image.height <= page_height:
            return [data]
        pages = []
        for top in range(0, image.height, page_height):
            crop = image.crop((0, top, image.width, min(top + page_height, image.height)))
            output = BytesIO()
            crop.save(output, format="PNG", optimize=True)
            pages.append(output.getvalue())
        return pages


async def render_fleet_pages(
    client,
    dashboard_ref,
    from_expr,
    to_expr,
    width,
    height,
    page_height,
    theme,
    tz,
):
    matches = await client.find_dashboards(dashboard_ref)
    if not matches:
        raise GrafanaError(f"no encontre el dashboard '{dashboard_ref}'.")
    if len(matches) > 1:
        raise GrafanaError(
            f"el dashboard '{dashboard_ref}' es ambiguo "
            f"({len(matches)} coincidencias)."
        )
    dashboard = await client.get_dashboard(matches[0]["uid"])
    image = await client.render_dashboard(
        dashboard["uid"],
        dashboard["slug"],
        from_expr,
        to_expr,
        width,
        height,
        theme,
        tz,
    )
    return dashboard, split_png_vertical(image, page_height)
