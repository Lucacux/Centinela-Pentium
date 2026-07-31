"""
grafana.py — Cliente modular de Grafana para Centinela.

Objetivo: ver en Discord *exactamente* los mismos graficos que los dashboards
de Grafana, con descubrimiento 100% dinamico. No se hardcodea ningun UID de
dashboard ni panelId: todo se lee en caliente via la API de Grafana. Si manana
se agrega un dashboard o un panel nuevo en Grafana, aparece solo en el bot sin
tocar codigo.

Depende de:
  - La API de Grafana (lectura): /api/search, /api/dashboards/uid/<uid>.
  - El endpoint /render (imagen PNG del panel), que requiere el plugin
    `grafana-image-renderer` instalado en el servidor de Grafana. Si el plugin
    no esta, /render devuelve una imagen de error fija (478x208) que este
    cliente detecta y reporta con un mensaje claro en vez de postear basura.

Auth: token Bearer de un service account de Grafana (rol Viewer alcanza).
"""

import re
import struct
import asyncio
import aiohttp

# Imagen de error que Grafana devuelve cuando el plugin de render no esta
# instalado ("No image renderer available/installed"). Tiene tamano fijo.
_RENDERER_MISSING_SIZE = (478, 208)
_RENDER_RETRY_DELAYS = (0, 2, 6)
_RETRYABLE_RENDER_STATUS = {429, 500, 502, 503, 504}

_SLUG_RE = re.compile(r"[^a-z0-9]+")
# rangos relativos aceptados como atajo: 15m, 6h, 24h, 7d, 2w...
_RANGE_RE = re.compile(r"^\d+[smhdwMy]$")


class GrafanaError(Exception):
    """Error operativo de Grafana con mensaje apto para mostrar en Discord."""


def slugify(text):
    s = _SLUG_RE.sub("-", (text or "").lower()).strip("-")
    return s or "d"


def parse_range(text, default="6h"):
    """Traduce un rango humano a (from, to) para la API de Grafana.

    Acepta atajos ('6h', '24h', '7d'), expresiones nativas ('now-1h') o vacio.
    """
    text = (text or default).strip()
    if text.startswith("now"):
        return text, "now"
    if _RANGE_RE.match(text):
        return f"now-{text}", "now"
    # cualquier cosa rara -> default seguro
    return f"now-{default}", "now"


def png_size(data):
    """(width, height) leyendo el IHDR de un PNG, o None si no es PNG valido."""
    if len(data) < 24 or data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", data[16:24])


class GrafanaClient:
    """Cliente async minimalista para descubrir y renderizar paneles."""

    def __init__(self, base_url, token, timeout=45):
        self.base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    # ---- HTTP helpers -----------------------------------------------------
    async def _get_json(self, path, params=None):
        try:
            async with aiohttp.ClientSession(timeout=self._timeout) as s:
                async with s.get(self.base + path, headers=self._headers, params=params) as r:
                    if r.status == 401:
                        raise GrafanaError("token invalido o sin permisos (401).")
                    if r.status != 200:
                        raise GrafanaError(f"GET {path} -> HTTP {r.status}")
                    return await r.json()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            raise GrafanaError(
                f"no pude conectar a Grafana ({self.base}): {e}. "
                "Revisá que el bot tenga ruta/firewall hacia el server."
            )

    async def _get_bytes(self, path, params=None):
        last_connection_error = None
        total_attempts = len(_RENDER_RETRY_DELAYS)
        for attempt, delay in enumerate(_RENDER_RETRY_DELAYS, start=1):
            if delay:
                await asyncio.sleep(delay)
            try:
                async with aiohttp.ClientSession(timeout=self._timeout) as s:
                    async with s.get(
                        self.base + path,
                        headers=self._headers,
                        params=params,
                    ) as r:
                        body = await r.read()
                        if r.status != 200:
                            error = GrafanaError(
                                f"render -> HTTP {r.status} "
                                f"(intento {attempt}/{total_attempts})"
                            )
                            if (
                                r.status in _RETRYABLE_RENDER_STATUS
                                and attempt < total_attempts
                            ):
                                continue
                            raise error
                        ctype = r.headers.get("Content-Type", "")
                        if "image" not in ctype:
                            raise GrafanaError(
                                f"el servidor devolvio '{ctype}', no una imagen."
                            )
                        return body
            except GrafanaError:
                raise
            except (aiohttp.ClientError, asyncio.TimeoutError) as error:
                last_connection_error = error
                if attempt < total_attempts:
                    continue

        raise GrafanaError(
            f"no pude conectar a Grafana ({self.base}) tras "
            f"{total_attempts} intentos: {last_connection_error}. "
            "Revisá que el bot tenga ruta/firewall hacia el server."
        )

    # ---- Descubrimiento (dinamico) ---------------------------------------
    async def health(self):
        return await self._get_json("/api/health")

    async def list_dashboards(self):
        data = await self._get_json(
            "/api/search", params={"type": "dash-db", "limit": "500"}
        )
        return [
            {"uid": d["uid"], "title": d["title"], "folder": d.get("folderTitle", "General")}
            for d in data
        ]

    async def find_dashboards(self, query):
        """Resuelve un dashboard por uid exacto o por substring del titulo.

        Devuelve una lista de coincidencias: 0 = no encontrado, 1 = univoco,
        >1 = ambiguo (el caller muestra las opciones).
        """
        q = (query or "").strip().lower()
        dashboards = await self.list_dashboards()
        by_uid = [d for d in dashboards if d["uid"].lower() == q]
        if by_uid:
            return by_uid
        by_title_exact = [d for d in dashboards if d["title"].lower() == q]
        if by_title_exact:
            return by_title_exact
        return [d for d in dashboards if q in d["title"].lower()]

    async def get_dashboard(self, uid):
        """Devuelve dict con uid, title, slug y la lista aplanada de paneles.

        Aplana recursivamente las 'rows' (colapsadas o expandidas) y deduplica
        por id, de modo que cualquier panel del dashboard queda listable sin
        importar como este organizado visualmente.
        """
        data = await self._get_json(f"/api/dashboards/uid/{uid}")
        dash = data["dashboard"]
        panels = []
        seen = set()

        def walk(items):
            for p in items or []:
                if p.get("type") == "row":
                    walk(p.get("panels"))
                    continue
                pid = p.get("id")
                if pid is None or pid in seen:
                    continue
                seen.add(pid)
                panels.append(
                    {
                        "id": pid,
                        "title": p.get("title") or f"panel {pid}",
                        "type": p.get("type", "?"),
                    }
                )

        walk(dash.get("panels"))
        return {
            "uid": dash.get("uid", uid),
            "title": dash.get("title", uid),
            "slug": slugify(dash.get("title")),
            "panels": panels,
        }

    @staticmethod
    def resolve_panel(panels, ref):
        """Encuentra un panel por id numerico o por substring del titulo."""
        ref = (ref or "").strip()
        if ref.isdigit():
            pid = int(ref)
            for p in panels:
                if p["id"] == pid:
                    return [p]
            return []
        low = ref.lower()
        exact = [p for p in panels if p["title"].lower() == low]
        if exact:
            return exact
        return [p for p in panels if low in p["title"].lower()]

    # ---- Render (imagen exacta de Grafana) -------------------------------
    def _check_renderer(self, body):
        if png_size(body) == _RENDERER_MISSING_SIZE:
            raise GrafanaError(
                "el plugin `grafana-image-renderer` no esta instalado/activo "
                "en el servidor de Grafana; no puedo generar la imagen."
            )

    async def render_panel(
        self, uid, slug, panel_id, from_expr="now-6h", to_expr="now",
        width=1000, height=500, theme="dark", tz="browser", variables=None,
    ):
        """PNG de un panel individual (endpoint /render/d-solo)."""
        params = {
            "panelId": str(panel_id),
            "from": from_expr,
            "to": to_expr,
            "width": str(width),
            "height": str(height),
            "theme": theme,
            "tz": tz,
        }
        if variables:
            params.update(variables)  # p.ej. {"var-node": "192.168.2.10:9100"}
        body = await self._get_bytes(f"/render/d-solo/{uid}/{slug}", params=params)
        self._check_renderer(body)
        return body

    async def render_panel_by_ref(
        self, dashboard_ref, panel_ref, from_expr="now-6h", to_expr="now",
        width=1000, height=500, theme="dark", tz="browser", variables=None,
    ):
        """Resuelve dashboard/panel por UID, ID o titulo y devuelve su PNG.

        El resultado es ``(dashboard, panel, imagen)``. Exigir coincidencias
        univocas evita que una busqueda parcial cambie silenciosamente de panel
        cuando se agregan dashboards o paneles nuevos.
        """
        dashboards = await self.find_dashboards(dashboard_ref)
        if not dashboards:
            raise GrafanaError(
                f"no encontre el dashboard '{dashboard_ref}'."
            )
        if len(dashboards) > 1:
            raise GrafanaError(
                f"el dashboard '{dashboard_ref}' es ambiguo "
                f"({len(dashboards)} coincidencias)."
            )

        dashboard = await self.get_dashboard(dashboards[0]["uid"])
        panels = self.resolve_panel(dashboard["panels"], panel_ref)
        if not panels:
            raise GrafanaError(
                f"no encontre el panel '{panel_ref}' en "
                f"'{dashboard['title']}'."
            )
        if len(panels) > 1:
            raise GrafanaError(
                f"el panel '{panel_ref}' es ambiguo "
                f"({len(panels)} coincidencias)."
            )

        panel = panels[0]
        image = await self.render_panel(
            dashboard["uid"], dashboard["slug"], panel["id"],
            from_expr, to_expr, width, height, theme, tz, variables,
        )
        return dashboard, panel, image

    async def render_dashboard(
        self, uid, slug, from_expr="now-6h", to_expr="now",
        width=1000, height=1200, theme="dark", tz="browser", variables=None,
    ):
        """PNG del dashboard completo (endpoint /render/d, modo kiosk)."""
        params = {
            "from": from_expr,
            "to": to_expr,
            "width": str(width),
            "height": str(height),
            "theme": theme,
            "tz": tz,
            "kiosk": "true",
        }
        if variables:
            params.update(variables)
        body = await self._get_bytes(f"/render/d/{uid}/{slug}", params=params)
        self._check_renderer(body)
        return body
