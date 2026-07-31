#!/usr/bin/env python3
"""Idempotently add the runtime endpoint inventory to Grafana."""

import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import urllib.error
import urllib.request

from dotenv import load_dotenv


PANEL_TITLE = "Endpoints — contenedores + servicios"


def request_json(base, token, path, payload=None):
    data = (
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if payload is not None else None
    )
    request = urllib.request.Request(
        f"{base.rstrip('/')}{path}",
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST" if payload is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")[-1000:]
        raise RuntimeError(f"Grafana HTTP {error.code}: {detail}") from error


def runtime_panel(panel_id, y):
    return {
        "id": panel_id,
        "title": PANEL_TITLE,
        "description": (
            "Endpoints descubiertos localmente. Incluye puertos publicados de "
            "contenedores, redes internas y servicios systemd no contenerizados."
        ),
        "type": "table",
        "datasource": {"type": "prometheus", "uid": "prometheus"},
        "gridPos": {"h": 10, "w": 24, "x": 0, "y": y},
        "options": {
            "showHeader": True,
            "cellHeight": "sm",
            "footer": {"show": False},
        },
        "fieldConfig": {
            "defaults": {
                "custom": {
                    "align": "auto",
                    "cellOptions": {"type": "auto"},
                    "filterable": True,
                },
            },
            "overrides": [
                {
                    "matcher": {"id": "byName", "options": "Endpoint"},
                    "properties": [{"id": "custom.width", "value": 230}],
                },
                {
                    "matcher": {"id": "byName", "options": "Servicio"},
                    "properties": [{"id": "custom.width", "value": 240}],
                },
                {
                    "matcher": {"id": "byName", "options": "Ámbito"},
                    "properties": [
                        {
                            "id": "mappings",
                            "value": [{
                                "type": "value",
                                "options": {
                                    "lan": {"text": "LAN"},
                                    "local": {"text": "Solo localhost"},
                                    "interface": {"text": "Interfaz"},
                                    "container-network": {
                                        "text": "Red del contenedor"
                                    },
                                },
                            }],
                        },
                    ],
                },
            ],
        },
        "targets": [{
            "datasource": {"type": "prometheus", "uid": "prometheus"},
            "editorMode": "code",
            "expr": 'centinela_runtime_endpoint_info{host=~"$host"}',
            "format": "table",
            "instant": True,
            "legendFormat": "__auto",
            "range": False,
            "refId": "A",
        }],
        "transformations": [{
            "id": "organize",
            "options": {
                "excludeByName": {
                    "Time": True,
                    "Value": True,
                    "__name__": True,
                    "bind": True,
                    "instance": True,
                    "job": True,
                    "state": True,
                },
                "indexByName": {
                    "host": 0,
                    "runtime": 1,
                    "service": 2,
                    "endpoint": 3,
                    "ip": 4,
                    "port": 5,
                    "protocol": 6,
                    "scope": 7,
                },
                "renameByName": {
                    "host": "Host",
                    "runtime": "Tipo",
                    "service": "Servicio",
                    "endpoint": "Endpoint",
                    "ip": "IP",
                    "port": "Puerto",
                    "protocol": "Protocolo",
                    "scope": "Ámbito",
                },
            },
        }],
    }


def backup(backup_dir, uid, response):
    destination = Path(backup_dir)
    destination.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = destination / f"grafana-{uid}-{stamp}.json"
    path.write_text(
        json.dumps(response, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    os.chmod(path, 0o600)
    return path


def save_dashboard(base, token, response, message):
    dashboard = response["dashboard"]
    return request_json(base, token, "/api/dashboards/db", {
        "dashboard": dashboard,
        "folderUid": response.get("meta", {}).get("folderUid", ""),
        "overwrite": True,
        "message": message,
    })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--backup-dir",
        default=str(Path.home() / ".local/share/centinela/grafana-backups"),
    )
    parser.add_argument("--dry-run", action="store_true")
    options = parser.parse_args()
    load_dotenv()
    base = os.getenv("GRAFANA_URL", "").strip()
    token = os.getenv("GRAFANA_TOKEN", "").strip()
    if not base or not token:
        raise SystemExit("GRAFANA_URL and GRAFANA_TOKEN are required")

    containers = request_json(base, token, "/api/dashboards/uid/containers")
    dashboard = containers["dashboard"]
    panels = dashboard.setdefault("panels", [])
    existing = next(
        (panel for panel in panels if panel.get("title") == PANEL_TITLE), None
    )
    panel_id = (
        existing.get("id")
        if existing else max((panel.get("id", 0) for panel in panels), default=0) + 1
    )
    if existing:
        y = existing.get("gridPos", {}).get("y", 0)
        panels[panels.index(existing)] = runtime_panel(panel_id, y)
    else:
        y = max(
            (
                panel.get("gridPos", {}).get("y", 0)
                + panel.get("gridPos", {}).get("h", 0)
                for panel in panels
            ),
            default=0,
        )
        panels.append(runtime_panel(panel_id, y))
    dashboard["title"] = "Contenedores + servicios"

    fleet = request_json(base, token, "/api/dashboards/uid/fleet-overview")
    for link in fleet["dashboard"].get("links", []):
        if link.get("url", "").startswith("/d/containers/"):
            link["title"] = "Contenedores + servicios"

    if options.dry_run:
        print(json.dumps({
            "containers_title": dashboard["title"],
            "panel": PANEL_TITLE,
            "panel_id": panel_id,
            "fleet_link_updated": True,
        }, ensure_ascii=False))
        return

    first_backup = backup(options.backup_dir, "containers", containers)
    second_backup = backup(options.backup_dir, "fleet-overview", fleet)
    save_dashboard(
        base, token, containers,
        "Centinela: endpoints de contenedores y servicios systemd",
    )
    save_dashboard(
        base, token, fleet,
        "Centinela: renombrar enlace de contenedores y servicios",
    )
    print(json.dumps({
        "updated": ["containers", "fleet-overview"],
        "backups": [str(first_backup), str(second_backup)],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
