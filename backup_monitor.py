"""backup_monitor.py — Estado del sistema de backups de la flota.

Lee el sistema de backups Borg (repo `homelab-backup`: Ansible + Borg 1.x +
borgmatic, append-only) **por sus métricas**, no por SSH a cada host.

Por qué por métricas y no por SSH
---------------------------------
Cada corrida de backup escribe su resultado en el textfile collector de
node_exporter, que Prometheus ya scrapea. Consultar Prometheus da tres cosas
que SSH no da: una sola credencial en vez de N, funciona aunque el host esté
apagado a la hora de preguntar (el último valor sigue en la TSDB), y no
inventa un segundo camino de acceso privilegiado a la flota.

Contrato de métricas (lo escriben los scripts de homelab-backup)
----------------------------------------------------------------
Cliente — `scripts/run-backup.sh` → `backup.prom`:
    backup_last_success_timestamp_seconds{host,repo}
    backup_last_exit_code{host,repo}
    backup_last_duration_seconds{host,repo}
    backup_repo_size_bytes{host,repo}

Repo host — `scripts/borg-maintenance.sh` → `borg_repo_<host>.prom`:
    borg_repo_size_bytes{host,repo}
    borg_repo_archives{host,repo}
    borg_repo_host_free_bytes{host}
    borg_maintenance_last_success_timestamp_seconds{host,repo}
    borg_check_last_success_timestamp_seconds{host,repo}

Repo host — `scripts/restore-test.sh` → `borg_restore_test_<host>.prom`:
    backup_restore_test_last_success_timestamp_seconds{host,repo}
    backup_canary_age_hours{host,repo}

En las métricas del repo host, `repo` es el *tenant*: de quién son los datos.

Nada de esta infra está hardcodeado
-----------------------------------
No hay una lista de hosts, de repos ni de tenants en este módulo. Todo sale de
las etiquetas de las series: si mañana entra un host nuevo al sistema de
backups, aparece solo en el reporte. Lo único fijo son los nombres de las
métricas, que son el contrato del repo de backups.

Por qué `last_over_time`
------------------------
Prometheus olvida una serie a los ~5 min de que el exporter deja de
responder. Consultada al desnudo, un host cuyo node_exporter murió
*desaparece* del reporte, que es exactamente el modo de falla que uno quiere
ver. `last_over_time(<metrica>[Nd])` lo retiene con su último valor conocido,
así el host se muestra en rojo por backup viejo en vez de esfumarse.

Horarios
--------
Todo en hora local naive, igual que el resto del Centinela: los epoch de
Prometheus se convierten con `datetime.fromtimestamp()` y se comparan contra
`datetime.now()`. Mezclar naive con aware acá fue un bug real en otro bot de
la flota.
"""

from __future__ import annotations

import asyncio
import glob
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import aiohttp

from alerts import CRITICAL, NO_DATA, OK, WARNING

__all__ = [
    "BackupMonitorError",
    "BackupPolicy",
    "FleetBackupReport",
    "JobStatus",
    "LocalRepoStatus",
    "RepoStatus",
    "ReportView",
    "Sample",
    "AlertState",
    "build_report",
    "collect_report",
    "discover_prometheus_datasource",
    "direct_source",
    "grafana_proxy_source",
    "inspect_local_repo",
    "local_status_from_payload",
    "parse_instant_vector",
    "render_fleet",
    "render_local",
]


class BackupMonitorError(Exception):
    """Error operativo con un mensaje en castellano apto para postear."""


# ── Severidades ─────────────────────────────────────────────────────────────
# Se reusa el vocabulario de alerts.py a propósito: dos escalas de severidad en
# el mismo bot es una garantía de que los colores dejen de significar lo mismo.
_SEVERITY_RANK = {OK: 0, NO_DATA: 1, WARNING: 2, CRITICAL: 3}

SEVERITY_COLOR = {
    OK: 0x2ECC71,
    NO_DATA: 0x95A5A6,
    WARNING: 0xE67E22,
    CRITICAL: 0xFF0000,
}

SEVERITY_EMOJI = {OK: "✅", NO_DATA: "⚪", WARNING: "🟠", CRITICAL: "🔴"}

SEVERITY_LABEL = {
    OK: "Al día",
    NO_DATA: "Sin datos",
    WARNING: "Degradado",
    CRITICAL: "Crítico",
}


def worst(severities) -> str:
    """La severidad más grave de un iterable. OK si viene vacío."""
    return max(severities, key=lambda s: _SEVERITY_RANK.get(s, 0), default=OK)


# ── Nombres de las métricas (el contrato con homelab-backup) ────────────────
M_LAST_SUCCESS = "backup_last_success_timestamp_seconds"
M_EXIT_CODE = "backup_last_exit_code"
M_DURATION = "backup_last_duration_seconds"
M_CLIENT_SIZE = "backup_repo_size_bytes"
M_RESTORE_TEST = "backup_restore_test_last_success_timestamp_seconds"
M_CANARY_AGE = "backup_canary_age_hours"
M_REPO_SIZE = "borg_repo_size_bytes"
M_REPO_ARCHIVES = "borg_repo_archives"
M_REPO_FREE = "borg_repo_host_free_bytes"
M_PRUNE = "borg_maintenance_last_success_timestamp_seconds"
M_CHECK = "borg_check_last_success_timestamp_seconds"

METRICS = (
    M_LAST_SUCCESS,
    M_EXIT_CODE,
    M_DURATION,
    M_CLIENT_SIZE,
    M_RESTORE_TEST,
    M_CANARY_AGE,
    M_REPO_SIZE,
    M_REPO_ARCHIVES,
    M_REPO_FREE,
    M_PRUNE,
    M_CHECK,
)

_GIB = 1024 ** 3


# ── Política de umbrales ────────────────────────────────────────────────────
@dataclass(frozen=True)
class BackupPolicy:
    """Umbrales del reporte. Todo configurable: los timers son del usuario.

    Los defaults salen de los `OnCalendar` de homelab-backup: backup diario
    03:00 (+15 min de jitter), prune semanal, restore-test semanal, check
    mensual. El margen extra es para que un host que se enciende tarde no
    dispare rojo en el primer minuto.

    Los tres umbrales críticos son, a propósito, los mismos que las alertas de
    Grafana que define el RUNBOOK del repo de backups (48 h sin backup, 14 d
    sin restauración verificada, 30 GB libres). Que Discord y Grafana digan
    cosas distintas sobre el mismo repo entrena a no creerle a ninguno.
    """

    stale_warning: timedelta = timedelta(hours=26)
    stale_critical: timedelta = timedelta(hours=48)
    restore_test_warning: timedelta = timedelta(days=8)
    restore_test_critical: timedelta = timedelta(days=14)
    prune_warning: timedelta = timedelta(days=10)
    check_warning: timedelta = timedelta(days=40)
    canary_warning: timedelta = timedelta(hours=26)
    free_warning_bytes: float = 30 * _GIB
    free_critical_bytes: float = 10 * _GIB
    lookback_days: int = 14

    @classmethod
    def from_env(cls, env=None):
        env = os.environ if env is None else env

        def hours(name, default):
            return timedelta(hours=float(env.get(name, default)))

        def days(name, default):
            return timedelta(days=float(env.get(name, default)))

        return cls(
            stale_warning=hours("BACKUP_STALE_WARNING_HOURS", 26),
            stale_critical=hours("BACKUP_STALE_CRITICAL_HOURS", 48),
            restore_test_warning=days("BACKUP_RESTORE_TEST_WARNING_DAYS", 8),
            restore_test_critical=days("BACKUP_RESTORE_TEST_CRITICAL_DAYS", 14),
            prune_warning=days("BACKUP_PRUNE_WARNING_DAYS", 10),
            check_warning=days("BACKUP_CHECK_WARNING_DAYS", 40),
            canary_warning=hours("BACKUP_CANARY_WARNING_HOURS", 26),
            free_warning_bytes=float(env.get("BACKUP_FREE_WARNING_GB", 30)) * _GIB,
            free_critical_bytes=float(env.get("BACKUP_FREE_CRITICAL_GB", 10)) * _GIB,
            lookback_days=int(env.get("BACKUP_METRIC_LOOKBACK_DAYS", 14)),
        )


# ── Muestras y parseo ───────────────────────────────────────────────────────
@dataclass(frozen=True)
class Sample:
    """Un punto de una consulta instantánea, con sus etiquetas."""

    labels: dict
    value: float

    @property
    def host(self) -> str:
        return self.labels.get("host") or self.labels.get("instance") or "?"

    @property
    def repo(self) -> str:
        return self.labels.get("repo") or "?"


def parse_instant_vector(payload):
    """Traduce la respuesta de `/api/v1/query` a una lista de `Sample`.

    Descarta puntos no numéricos y NaN en vez de reventar: una serie rota no
    tiene por qué tirar abajo el reporte de las otras.
    """
    if not isinstance(payload, dict):
        raise BackupMonitorError("Prometheus devolvió algo que no es JSON de consulta.")
    if payload.get("status") != "success":
        detail = payload.get("error") or payload.get("errorType") or "sin detalle"
        raise BackupMonitorError(f"Prometheus rechazó la consulta: {detail}")
    data = payload.get("data") or {}
    result_type = data.get("resultType")
    if result_type not in (None, "vector"):
        raise BackupMonitorError(
            f"se esperaba un vector instantáneo y llegó '{result_type}'."
        )
    samples = []
    for item in data.get("result") or []:
        if not isinstance(item, dict):
            continue
        pair = item.get("value") or []
        if len(pair) < 2:
            continue
        try:
            value = float(pair[1])
        except (TypeError, ValueError):
            continue
        if value != value:  # NaN
            continue
        labels = item.get("metric") or {}
        samples.append(Sample(dict(labels), value))
    return samples


# ── Transporte ──────────────────────────────────────────────────────────────
class HttpJson:
    """Cliente JSON async mínimo, con los errores ya traducidos."""

    def __init__(self, base_url, *, headers=None, timeout=20, session_factory=None):
        self.base = (base_url or "").rstrip("/")
        self._headers = dict(headers or {})
        self._timeout = timeout
        self._session_factory = session_factory or aiohttp.ClientSession

    async def get(self, path, params=None):
        url = self.base + path
        try:
            session = self._session_factory(
                timeout=aiohttp.ClientTimeout(total=self._timeout)
            )
            async with session as client:
                async with client.get(url, headers=self._headers, params=params) as r:
                    if r.status in (401, 403):
                        raise BackupMonitorError(
                            f"credenciales rechazadas al consultar {path} "
                            f"(HTTP {r.status}). Revisá el token."
                        )
                    if r.status == 404:
                        raise BackupMonitorError(
                            f"{path} no existe (HTTP 404). "
                            "¿El datasource o la URL son los correctos?"
                        )
                    if r.status != 200:
                        body = (await r.text())[:200]
                        raise BackupMonitorError(f"GET {path} → HTTP {r.status}: {body}")
                    return await r.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError) as error:
            raise BackupMonitorError(
                f"no pude conectar a {self.base}: {error}. "
                "Revisá que el bot tenga ruta y firewall hacia el server."
            ) from error


class PrometheusSource:
    """Consultas instantáneas, sin importar cómo se llega a Prometheus."""

    def __init__(self, http, query_path="/api/v1/query", origin=""):
        self._http = http
        self._path = query_path
        self.origin = origin

    async def query(self, expr):
        return parse_instant_vector(await self._http.get(self._path, {"query": expr}))


def direct_source(url, *, timeout=20, session_factory=None):
    """Prometheus expuesto directo (`PROMETHEUS_URL`)."""
    return PrometheusSource(
        HttpJson(url, timeout=timeout, session_factory=session_factory),
        origin=f"Prometheus {url}",
    )


def grafana_proxy_source(
    grafana_url, token, datasource_uid, *, timeout=20, session_factory=None
):
    """Prometheus vía el proxy de datasource de Grafana.

    Es el camino barato en esta flota: el Centinela ya tiene `GRAFANA_URL` y
    un token Viewer que funcionan, y Prometheus suele estar cerrado al resto
    de la red mientras Grafana está abierto. Cero credenciales nuevas, cero
    reglas de firewall nuevas.
    """
    http = HttpJson(
        grafana_url,
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
        session_factory=session_factory,
    )
    return PrometheusSource(
        http,
        query_path=f"/api/datasources/proxy/uid/{datasource_uid}/api/v1/query",
        origin=f"Grafana {grafana_url} (datasource {datasource_uid})",
    )


def _walk_datasource_uids(node):
    """UIDs de datasources Prometheus dentro de un JSON de dashboard."""
    if isinstance(node, dict):
        if node.get("type") == "prometheus":
            uid = node.get("uid")
            # Las variables de template (`${DS_PROM}`) no sirven para el proxy.
            if isinstance(uid, str) and uid and "$" not in uid:
                yield uid
        for value in node.values():
            yield from _walk_datasource_uids(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk_datasource_uids(value)


async def discover_prometheus_datasource(http, *, max_dashboards=15):
    """UID del datasource Prometheus, descubierto en caliente.

    Dos caminos, en orden de privilegio: `/api/datasources` (necesita un token
    de admin) y, si no, los paneles de los dashboards, que un token Viewer sí
    puede leer. Descubrir en vez de hardcodear el UID es el mismo requisito de
    diseño que tiene el comando `!grafana`: si el datasource se recrea, el bot
    tiene que seguir andando sin tocar código.
    """
    try:
        listing = await http.get("/api/datasources")
        for entry in listing or []:
            if isinstance(entry, dict) and entry.get("type") == "prometheus":
                uid = entry.get("uid")
                if uid:
                    return uid
    except BackupMonitorError:
        pass  # token Viewer: era esperable, seguimos por los dashboards

    dashboards = await http.get("/api/search", {"type": "dash-db", "limit": 100})
    for entry in (dashboards or [])[:max_dashboards]:
        uid = entry.get("uid") if isinstance(entry, dict) else None
        if not uid:
            continue
        try:
            detail = await http.get(f"/api/dashboards/uid/{uid}")
        except BackupMonitorError:
            continue
        for found in _walk_datasource_uids(detail.get("dashboard") or detail):
            return found
    raise BackupMonitorError(
        "no encontré ningún datasource Prometheus en Grafana. "
        "Configurá BACKUP_PROMETHEUS_DATASOURCE con el UID a mano."
    )


# ── Modelo de dominio ───────────────────────────────────────────────────────
@dataclass(frozen=True)
class Assessment:
    severity: str
    reasons: tuple = ()


@dataclass(frozen=True)
class JobStatus:
    """Un backup de un host hacia un repo concreto (lado cliente)."""

    host: str
    repo: str
    last_success: datetime = None
    exit_code: int = None
    duration_seconds: float = None
    size_bytes: float = None

    def age(self, now):
        return None if self.last_success is None else now - self.last_success

    def assess(self, policy, now):
        reasons = []
        severity = OK
        age = self.age(now)
        if age is None:
            severity = CRITICAL
            reasons.append("sin ningún backup exitoso registrado")
        elif age >= policy.stale_critical:
            severity = CRITICAL
            reasons.append(f"último éxito hace {format_age(age)}")
        elif age >= policy.stale_warning:
            severity = WARNING
            reasons.append(f"último éxito hace {format_age(age)}")
        if self.exit_code not in (None, 0):
            reasons.append(f"la última corrida falló (exit {self.exit_code})")
            severity = worst([severity, WARNING])
        return Assessment(severity, tuple(reasons))


@dataclass(frozen=True)
class RepoStatus:
    """Un tenant dentro de un repo host: retención, verificación y canario."""

    host: str
    tenant: str
    size_bytes: float = None
    archives: float = None
    last_prune: datetime = None
    last_check: datetime = None
    last_restore_test: datetime = None
    canary_age_hours: float = None

    def assess(self, policy, now):
        reasons = []
        severity = OK

        if self.last_restore_test is None:
            severity = worst([severity, WARNING])
            reasons.append("nunca se verificó una restauración")
        else:
            age = now - self.last_restore_test
            if age >= policy.restore_test_critical:
                severity = CRITICAL
                reasons.append(f"restauración verificada hace {format_age(age)}")
            elif age >= policy.restore_test_warning:
                severity = worst([severity, WARNING])
                reasons.append(f"restauración verificada hace {format_age(age)}")

        # El canario es lo único que distingue "repo sano" de "repo sano que
        # nadie está escribiendo": un timer muerto deja el repo impecable.
        if (
            self.canary_age_hours is not None
            and timedelta(hours=self.canary_age_hours) >= policy.canary_warning
        ):
            severity = worst([severity, WARNING])
            reasons.append(
                f"el canario del último archive tiene {self.canary_age_hours:.0f} h: "
                "el cliente no está escribiendo"
            )

        if self.last_prune is not None and now - self.last_prune >= policy.prune_warning:
            severity = worst([severity, WARNING])
            reasons.append(f"sin prune hace {format_age(now - self.last_prune)}")

        if self.last_check is not None and now - self.last_check >= policy.check_warning:
            severity = worst([severity, WARNING])
            reasons.append(f"sin check --verify-data hace {format_age(now - self.last_check)}")

        return Assessment(severity, tuple(reasons))


@dataclass(frozen=True)
class FleetBackupReport:
    """Foto del sistema de backups completo."""

    generated_at: datetime
    policy: BackupPolicy
    jobs: tuple = ()
    repos: tuple = ()
    free_bytes: dict = field(default_factory=dict)
    query_errors: tuple = ()
    origin: str = ""

    @property
    def is_empty(self):
        return not self.jobs and not self.repos and not self.free_bytes

    def job_assessments(self):
        return [(job, job.assess(self.policy, self.generated_at)) for job in self.jobs]

    def repo_assessments(self):
        return [(repo, repo.assess(self.policy, self.generated_at)) for repo in self.repos]

    def free_space_issues(self):
        """(host, bytes, severidad) para los repo hosts con poco espacio."""
        issues = []
        for host, free in sorted(self.free_bytes.items()):
            if free < self.policy.free_critical_bytes:
                issues.append((host, free, CRITICAL))
            elif free < self.policy.free_warning_bytes:
                issues.append((host, free, WARNING))
        return issues

    @property
    def severity(self):
        if self.is_empty:
            return NO_DATA
        severities = [a.severity for _, a in self.job_assessments()]
        severities += [a.severity for _, a in self.repo_assessments()]
        severities += [s for _, _, s in self.free_space_issues()]
        if self.query_errors:
            severities.append(WARNING)
        return worst(severities)

    @property
    def hosts(self):
        return sorted({job.host for job in self.jobs})


# ── Construcción del reporte ────────────────────────────────────────────────
def _timestamp(value):
    """Epoch → datetime local. `0` significa "nunca" en el contrato, no 1970."""
    if value is None or value <= 0:
        return None
    try:
        return datetime.fromtimestamp(value)
    except (OverflowError, OSError, ValueError):
        return None


def _index(samples_by_metric, metric):
    """{(host, repo): valor} para una métrica con etiquetas host/repo."""
    return {
        (s.host, s.repo): s.value for s in samples_by_metric.get(metric, ())
    }


def build_report(samples_by_metric, policy, now=None, *, query_errors=(), origin=""):
    """Arma el reporte a partir de las muestras. Función pura: sin red, sin reloj.

    El reloj entra por parámetro justamente porque toda la lógica de este
    módulo es "hace cuánto": un test que dependa de `datetime.now()` real no
    prueba nada.
    """
    now = now or datetime.now()

    last_success = _index(samples_by_metric, M_LAST_SUCCESS)
    exit_codes = _index(samples_by_metric, M_EXIT_CODE)
    durations = _index(samples_by_metric, M_DURATION)
    client_sizes = _index(samples_by_metric, M_CLIENT_SIZE)

    jobs = []
    for key in sorted(set(last_success) | set(exit_codes) | set(client_sizes)):
        host, repo = key
        code = exit_codes.get(key)
        jobs.append(
            JobStatus(
                host=host,
                repo=repo,
                last_success=_timestamp(last_success.get(key)),
                exit_code=None if code is None else int(code),
                duration_seconds=durations.get(key),
                size_bytes=client_sizes.get(key),
            )
        )

    repo_sizes = _index(samples_by_metric, M_REPO_SIZE)
    archives = _index(samples_by_metric, M_REPO_ARCHIVES)
    prunes = _index(samples_by_metric, M_PRUNE)
    checks = _index(samples_by_metric, M_CHECK)
    restore_tests = _index(samples_by_metric, M_RESTORE_TEST)
    canaries = _index(samples_by_metric, M_CANARY_AGE)

    repos = []
    keys = set(repo_sizes) | set(prunes) | set(checks) | set(restore_tests)
    for key in sorted(keys):
        host, tenant = key
        repos.append(
            RepoStatus(
                host=host,
                tenant=tenant,
                size_bytes=repo_sizes.get(key),
                archives=archives.get(key),
                last_prune=_timestamp(prunes.get(key)),
                last_check=_timestamp(checks.get(key)),
                last_restore_test=_timestamp(restore_tests.get(key)),
                canary_age_hours=canaries.get(key),
            )
        )

    free = {s.host: s.value for s in samples_by_metric.get(M_REPO_FREE, ())}

    return FleetBackupReport(
        generated_at=now,
        policy=policy,
        jobs=tuple(jobs),
        repos=tuple(repos),
        free_bytes=free,
        query_errors=tuple(query_errors),
        origin=origin,
    )


async def collect_report(source, policy, now=None, *, metrics=METRICS):
    """Consulta Prometheus y devuelve el reporte.

    Una consulta por métrica, en paralelo. Se podría hacer una sola con
    `{__name__=~"(backup|borg)_.*"}`, pero el nombre de la métrica no
    sobrevive de forma confiable a las funciones de rango, y una consulta que
    vuelve vacía en silencio es peor que once que fallan ruidosamente.
    """
    exprs = [f"last_over_time({metric}[{policy.lookback_days}d])" for metric in metrics]
    results = await asyncio.gather(
        *(source.query(expr) for expr in exprs), return_exceptions=True
    )

    samples_by_metric = {}
    errors = []
    for metric, result in zip(metrics, results, strict=True):
        if isinstance(result, Exception):
            errors.append(f"{metric}: {result}")
            continue
        samples_by_metric[metric] = result

    if not samples_by_metric:
        # Todas fallaron: es el server, no las series. Que se vea el error real.
        raise BackupMonitorError(
            errors[0] if errors else "Prometheus no devolvió ninguna serie."
        )

    return build_report(
        samples_by_metric,
        policy,
        now,
        query_errors=errors,
        origin=getattr(source, "origin", ""),
    )


# ── Repo local / agente remoto (compatibilidad con el esquema viejo) ────────
@dataclass(frozen=True)
class LocalRepoStatus:
    """Un repo Borg mirado desde el filesystem, sin métricas de por medio.

    Borg no crea archivos nuevos por backup: actualiza `index.*`. El mtime de
    ese índice es lo más cercano a "cuándo se escribió por última vez" que se
    puede sacar sin abrir el repo (que necesitaría la passphrase).
    """

    label: str = ""
    path: str = ""
    configured: bool = False
    exists: bool = False
    index_file: str = None
    last_modified: datetime = None
    size_bytes: float = None

    def assess(self, policy, now):
        if not self.configured:
            return Assessment(NO_DATA, ("no hay un repo local configurado",))
        if not self.exists:
            return Assessment(CRITICAL, (f"`{self.path}` no existe",))
        if self.last_modified is None:
            return Assessment(CRITICAL, ("no se encontró ningún `index.*` en el repo",))
        age = now - self.last_modified
        if age >= policy.stale_critical:
            return Assessment(CRITICAL, (f"sin escrituras hace {format_age(age)}",))
        if age >= policy.stale_warning:
            return Assessment(WARNING, (f"sin escrituras hace {format_age(age)}",))
        return Assessment(OK, ())


def inspect_local_repo(path, label="local", *, with_size=True):
    """Estado de un repo Borg en disco. Bloqueante: llamar en un thread."""
    if not path:
        return LocalRepoStatus(label=label)
    if not os.path.isdir(path):
        return LocalRepoStatus(label=label, path=path, configured=True, exists=False)

    candidates = glob.glob(os.path.join(path, "index.*"))
    index_file = max(candidates, key=os.path.getmtime) if candidates else None
    last_modified = (
        datetime.fromtimestamp(os.path.getmtime(index_file)) if index_file else None
    )

    size = None
    if with_size:
        size = 0
        for root, _, files in os.walk(path):
            for name in files:
                try:
                    size += os.path.getsize(os.path.join(root, name))
                except OSError:
                    continue

    return LocalRepoStatus(
        label=label,
        path=path,
        configured=True,
        exists=True,
        index_file=os.path.basename(index_file) if index_file else None,
        last_modified=last_modified,
        size_bytes=size,
    )


def local_status_from_payload(payload, label="remoto"):
    """Traduce la respuesta `backup` del agente remoto al mismo modelo.

    Que el nodo remoto y el local terminen en la misma dataclass es el punto:
    antes había dos formatos de embed que decían lo mismo con otras palabras y
    otros umbrales.
    """
    payload = payload or {}
    timestamp = payload.get("last_timestamp")
    return LocalRepoStatus(
        label=label,
        path=payload.get("path", ""),
        configured=bool(payload.get("configured")),
        exists=bool(payload.get("exists")),
        index_file=payload.get("index"),
        last_modified=_timestamp(timestamp),
        size_bytes=payload.get("size"),
    )


# ── Formato ─────────────────────────────────────────────────────────────────
def format_bytes(value):
    if value is None:
        return "—"
    value = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def format_age(delta):
    """Antigüedad legible de un vistazo en el celular: '3 d 4 h', '12 min'."""
    if delta is None:
        return "nunca"
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "en el futuro"
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days} d {hours} h"
    if hours:
        return f"{hours} h {minutes} min"
    if minutes:
        return f"{minutes} min"
    return f"{seconds} s"


def format_duration(seconds):
    if seconds is None:
        return "—"
    return format_age(timedelta(seconds=float(seconds)))


def _when(moment):
    return "nunca" if moment is None else moment.strftime("%d/%m %H:%M")


@dataclass(frozen=True)
class ViewField:
    name: str
    value: str
    inline: bool = False


@dataclass(frozen=True)
class ReportView:
    """Lo que hay que mostrar, sin saber nada de Discord.

    Separado a propósito: la lógica de qué está mal se testea sin instanciar
    un `discord.Embed`, y si mañana el reporte sale por otro canal (ntfy, un
    mail) no hay que reimplementar los umbrales.
    """

    title: str
    description: str = ""
    color: int = SEVERITY_COLOR[OK]
    fields: tuple = ()
    footer: str = ""


_FIELD_LIMIT = 1000
_MAX_FIELDS = 20


def _clip(text):
    return text if len(text) <= _FIELD_LIMIT else text[: _FIELD_LIMIT - 1] + "…"


def render_fleet(report, host_filter=None, *, title="Backups de la flota"):
    """Arma la vista del reporte de flota, opcionalmente filtrada por host."""
    severity = report.severity
    needle = (host_filter or "").strip().lower()

    if report.is_empty:
        return ReportView(
            title=f"⚪ {title}",
            description=(
                "El sistema de backups no está reportando métricas.\n"
                "O todavía no se desplegó, o el textfile collector de "
                "node_exporter no está llegando a Prometheus.\n\n"
                "Comprobar en un host: "
                "`ls -l /var/lib/node-exporter-textfile/backup.prom`"
            ),
            color=SEVERITY_COLOR[NO_DATA],
            footer=report.origin,
        )

    fields = []

    jobs = [
        (job, assessment)
        for job, assessment in report.job_assessments()
        if not needle or needle in job.host.lower()
    ]
    for job, assessment in jobs[:_MAX_FIELDS]:
        lines = [
            f"Último éxito: **{_when(job.last_success)}**"
            + (
                ""
                if job.last_success is None
                else f" (hace {format_age(job.age(report.generated_at))})"
            )
        ]
        if job.duration_seconds is not None:
            lines.append(f"Duración: {format_duration(job.duration_seconds)}")
        if job.size_bytes is not None:
            lines.append(f"Tamaño: {format_bytes(job.size_bytes)}")
        if job.exit_code is not None:
            lines.append(f"Exit code: `{job.exit_code}`")
        for reason in assessment.reasons:
            lines.append(f"⚠️ {reason}")
        fields.append(
            ViewField(
                name=f"{SEVERITY_EMOJI[assessment.severity]} {job.host} → {job.repo}",
                value=_clip("\n".join(lines)),
            )
        )

    repos = [
        (repo, assessment)
        for repo, assessment in report.repo_assessments()
        if not needle or needle in repo.host.lower() or needle in repo.tenant.lower()
    ]
    if repos:
        lines = []
        for repo, assessment in repos:
            head = (
                f"{SEVERITY_EMOJI[assessment.severity]} **{repo.host}/{repo.tenant}** — "
                f"{format_bytes(repo.size_bytes)}"
            )
            if repo.archives is not None:
                head += f", {int(repo.archives)} archives"
            lines.append(head)
            lines.append(
                f"    restauración: {_when(repo.last_restore_test)} · "
                f"prune: {_when(repo.last_prune)} · check: {_when(repo.last_check)}"
            )
            for reason in assessment.reasons:
                lines.append(f"    ⚠️ {reason}")
        fields.append(
            ViewField(name="🗄 Repositorios", value=_clip("\n".join(lines)))
        )

    free_bytes = {
        host: free
        for host, free in report.free_bytes.items()
        if not needle or needle in host.lower()
    }
    if free_bytes:
        degraded = {host: sev for host, _, sev in report.free_space_issues()}
        lines = [
            f"{SEVERITY_EMOJI.get(degraded.get(host), SEVERITY_EMOJI[OK])} "
            f"**{host}**: {format_bytes(free)} libres"
            for host, free in sorted(free_bytes.items())
        ]
        fields.append(
            ViewField(name="💽 Espacio en los repo hosts", value=_clip("\n".join(lines)))
        )

    if report.query_errors:
        fields.append(
            ViewField(
                name="⚠️ Consultas con error",
                value=_clip("\n".join(f"`{e}`" for e in report.query_errors[:5])),
            )
        )

    if needle:
        # Con filtro, el encabezado tiene que hablar de lo que se está
        # mostrando: un 🔴 global arriba de un host sano se lee como que el
        # host sano está roto.
        severity = worst(
            [assessment.severity for _, assessment in jobs]
            + [assessment.severity for _, assessment in repos]
        )

    ok_jobs = sum(1 for _, assessment in jobs if assessment.severity == OK)
    description = (
        f"**{SEVERITY_LABEL[severity]}** — {ok_jobs}/{len(jobs)} "
        f"{'backup' if len(jobs) == 1 else 'backups'} al día · "
        f"{len(repos)} {'repo verificado' if len(repos) == 1 else 'repos verificados'}"
    )
    if needle and not jobs and not repos and not free_bytes:
        description = f"Ningún host coincide con `{host_filter}`."

    return ReportView(
        title=f"{SEVERITY_EMOJI[severity]} {title}",
        description=description,
        color=SEVERITY_COLOR[severity],
        fields=tuple(fields),
        footer=report.origin,
    )


def render_local(status, policy, now=None, *, title=None):
    """Vista de un repo Borg suelto (el local o el del agente remoto)."""
    now = now or datetime.now()
    assessment = status.assess(policy, now)
    label = title or f"Backup Borg — {status.label}"

    if not status.configured:
        return ReportView(
            title=f"⚪ {label}",
            description="No hay `BACKUP_PATH` configurado en este host.",
            color=SEVERITY_COLOR[NO_DATA],
        )
    if not status.exists:
        return ReportView(
            title=f"🔴 {label}",
            description=f"`{status.path}` no existe.",
            color=SEVERITY_COLOR[CRITICAL],
        )

    fields = [
        ViewField(name="Índice", value=f"`{status.index_file or '—'}`"),
        ViewField(name="Última escritura", value=_when(status.last_modified), inline=True),
        ViewField(
            name="Antigüedad",
            value=format_age(None if status.last_modified is None else now - status.last_modified),
            inline=True,
        ),
        ViewField(name="Tamaño", value=format_bytes(status.size_bytes), inline=True),
    ]
    if assessment.reasons:
        fields.append(
            ViewField(name="Estado", value="\n".join(f"⚠️ {r}" for r in assessment.reasons))
        )
    return ReportView(
        title=f"{SEVERITY_EMOJI[assessment.severity]} {label}",
        description=SEVERITY_LABEL[assessment.severity],
        color=SEVERITY_COLOR[assessment.severity],
        fields=tuple(fields),
    )


# ── Estado de alerta ────────────────────────────────────────────────────────
class AlertState:
    """Decide cuándo hablar, para que el reporte no se vuelva ruido.

    Avisa en cada transición de severidad y, mientras siga degradado, repite
    cada `reminder`. Nunca manda un "todo bien" al arrancar: un bot que
    saluda cada vez que se reinicia entrena a ignorarlo.
    """

    def __init__(self, reminder=timedelta(hours=12)):
        self.reminder = reminder
        self.severity = None
        self.last_notified = None

    def should_notify(self, severity, now=None):
        now = now or datetime.now()
        previous, self.severity = self.severity, severity

        if previous is None:
            notify = severity != OK
        elif severity != previous:
            notify = True
        else:
            notify = (
                severity != OK
                and self.last_notified is not None
                and now - self.last_notified >= self.reminder
            )

        if notify:
            self.last_notified = now
        return notify
