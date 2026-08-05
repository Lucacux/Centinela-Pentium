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

Orquestador — `scripts/backup-orchestrator.py` → `backup-orchestrator.prom`:
    backup_run_state, backup_run_result, backup_run_duration_seconds
    backup_run_started_timestamp_seconds, backup_run_finished_timestamp_seconds
    backup_next_run_timestamp_seconds
    backup_run_host_state{host}, backup_run_host_woken{host}
    backup_run_host_duration_seconds{host}

Las primeras describen el CONTENIDO de los repos ("¿hay un backup reciente?").
Las del orquestador describen el PROCESO ("¿está corriendo uno ahora?"), y son
las que permiten avisar cuando un backup arranca en vez de solo cuando terminó.

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
    "RunAnnouncer",
    "RunStatus",
    "Sample",
    "AlertState",
    "build_report",
    "build_run_status",
    "collect_report",
    "collect_run_status",
    "discover_prometheus_datasource",
    "direct_source",
    "grafana_proxy_source",
    "inspect_local_repo",
    "local_status_from_payload",
    "parse_instant_vector",
    "render_fleet",
    "render_local",
    "render_run_finished",
    "render_run_progress",
    "render_run_started",
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
    08:00 (+15 min de jitter), prune semanal, restore-test semanal, check
    mensual. El margen extra es para que un host que se enciende tarde no
    dispare rojo en el primer minuto.

    Los umbrales son en horas transcurridas, no horarios: mover la ventana del
    backup (pasó de 03:00 a 08:00 el 2026-08-04) no los invalida.

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


def render_fleet(report, host_filter=None, *, title="Backups de la flota", run=None):
    """Arma la vista del reporte de flota, opcionalmente filtrada por host.

    `run` es el estado del orquestador. Va en el mismo reporte y no en uno
    aparte porque "cuándo es el próximo backup" es la primera pregunta que
    sigue a "cómo están los backups", y separarla obliga a pedir dos cosas.
    """
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

    if run is not None and run.present and not needle:
        lines = []
        if run.running:
            current = run.current_host
            lines.append(
                "🔄 **Hay un backup corriendo ahora**"
                + (f" — respaldando {current}" if current else "")
            )
        elif run.result is not None:
            lines.append(
                f"{SEVERITY_EMOJI[RESULT_SEVERITY.get(run.result, NO_DATA)]} "
                f"Última corrida: {RESULT_LABEL.get(run.result, '?')}"
                + (f" ({_when(run.finished)})" if run.finished else "")
            )
        lines.append(f"⏭ Próximo backup: {_next_run_line(run, report.generated_at)}")
        if run.woken_hosts:
            lines.append(f"🔌 Encendidos por WOL: {', '.join(run.woken_hosts)}")
        fields.append(ViewField(name="🗓 La corrida", value=_clip("\n".join(lines))))

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


# ── La corrida: qué está pasando ahora mismo ────────────────────────────────
# Las métricas de arriba describen el CONTENIDO de los repos ("¿hay un backup
# reciente?"). Estas describen el PROCESO ("¿está corriendo uno ahora?"), y las
# publica el orquestador de homelab-backup en server-mbp. Son las que permiten
# avisar cuando un backup arranca y no recién cuando terminó.
M_RUN_STATE = "backup_run_state"
M_RUN_STARTED = "backup_run_started_timestamp_seconds"
M_RUN_FINISHED = "backup_run_finished_timestamp_seconds"
M_RUN_DURATION = "backup_run_duration_seconds"
M_RUN_RESULT = "backup_run_result"
M_NEXT_RUN = "backup_next_run_timestamp_seconds"
M_RUN_HOST_STATE = "backup_run_host_state"
M_RUN_HOST_WOKEN = "backup_run_host_woken"
M_RUN_HOST_DURATION = "backup_run_host_duration_seconds"

# Una sola consulta trae las diez series. Se puede usar el regex sobre
# `__name__` acá (y no en el reporte de flota) porque estas son consultas
# instantáneas sin función de rango: el nombre sobrevive y llega en las
# etiquetas. Importa porque este poll corre cada minuto.
RUN_SELECTOR = '{__name__=~"backup_run_.*|backup_next_run_timestamp_seconds"}'

HOST_PENDING, HOST_RUNNING, HOST_OK, HOST_FAILED, HOST_SKIPPED = 0, 1, 2, 3, 4
RESULT_OK, RESULT_PARTIAL, RESULT_FAILED = 0, 1, 2

HOST_STATE_EMOJI = {
    HOST_PENDING: "⏳",
    HOST_RUNNING: "🔄",
    HOST_OK: "✅",
    HOST_FAILED: "❌",
    HOST_SKIPPED: "⏭",
}
HOST_STATE_LABEL = {
    HOST_PENDING: "pendiente",
    HOST_RUNNING: "corriendo",
    HOST_OK: "ok",
    HOST_FAILED: "falló",
    HOST_SKIPPED: "omitido",
}
RESULT_SEVERITY = {RESULT_OK: OK, RESULT_PARTIAL: WARNING, RESULT_FAILED: CRITICAL}
RESULT_LABEL = {
    RESULT_OK: "todos los hosts respaldados",
    RESULT_PARTIAL: "parcial: quedaron hosts sin respaldar",
    RESULT_FAILED: "falló: no se respaldó ningún host",
}


@dataclass(frozen=True)
class RunHost:
    name: str
    state: int = HOST_PENDING
    woken: bool = False
    duration: float | None = None

    @property
    def line(self) -> str:
        emoji = HOST_STATE_EMOJI.get(self.state, "⚪")
        parts = [f"{emoji} **{self.name}** — {HOST_STATE_LABEL.get(self.state, '?')}"]
        if self.duration:
            parts.append(f"({format_duration(self.duration)})")
        if self.woken:
            parts.append("🔌")
        return " ".join(parts)


@dataclass(frozen=True)
class RunStatus:
    """Foto de la corrida del orquestador. Sin red y sin Discord."""

    present: bool = False
    running: bool = False
    started: object = None
    finished: object = None
    duration: float | None = None
    result: int | None = None
    next_run: object = None
    hosts: tuple = ()

    @property
    def woken_hosts(self) -> tuple:
        return tuple(host.name for host in self.hosts if host.woken)

    @property
    def current_host(self):
        for host in self.hosts:
            if host.state == HOST_RUNNING:
                return host.name
        return None

    def counts(self) -> dict:
        states = [host.state for host in self.hosts]
        return {
            "total": len(states),
            "ok": states.count(HOST_OK),
            "failed": states.count(HOST_FAILED),
            "skipped": states.count(HOST_SKIPPED),
        }

    @property
    def severity(self) -> str:
        if not self.present:
            return NO_DATA
        if self.running:
            return OK
        return RESULT_SEVERITY.get(self.result, NO_DATA)


def group_by_metric_name(samples):
    """{nombre de métrica: [Sample]} a partir de una consulta con `__name__`."""
    grouped = {}
    for sample in samples:
        name = sample.labels.get("__name__")
        if name:
            grouped.setdefault(name, []).append(sample)
    return grouped


def _scalar(samples_by_metric, metric):
    values = [s.value for s in samples_by_metric.get(metric, ())]
    return max(values) if values else None


def build_run_status(samples_by_metric) -> RunStatus:
    """Arma la foto de la corrida. Función pura: sin red, sin reloj."""
    state = _scalar(samples_by_metric, M_RUN_STATE)
    if state is None:
        return RunStatus(present=False)

    by_host = {}
    for metric, key in (
        (M_RUN_HOST_STATE, "state"),
        (M_RUN_HOST_WOKEN, "woken"),
        (M_RUN_HOST_DURATION, "duration"),
    ):
        for sample in samples_by_metric.get(metric, ()):
            by_host.setdefault(sample.host, {})[key] = sample.value

    hosts = tuple(
        RunHost(
            name=name,
            state=int(values.get("state", HOST_PENDING)),
            woken=bool(values.get("woken")),
            duration=values.get("duration") or None,
        )
        # Orden estable y previsible: primero lo que está pasando, después lo
        # que salió mal. Un reporte que reordena solo es un reporte que hay que
        # leer entero cada vez.
        for name, values in sorted(by_host.items())
    )
    order = {HOST_RUNNING: 0, HOST_FAILED: 1, HOST_SKIPPED: 2, HOST_PENDING: 3, HOST_OK: 4}
    hosts = tuple(sorted(hosts, key=lambda h: (order.get(h.state, 9), h.name)))

    result = _scalar(samples_by_metric, M_RUN_RESULT)
    return RunStatus(
        present=True,
        running=state >= 1,
        started=_timestamp(_scalar(samples_by_metric, M_RUN_STARTED)),
        finished=_timestamp(_scalar(samples_by_metric, M_RUN_FINISHED)),
        duration=_scalar(samples_by_metric, M_RUN_DURATION),
        result=None if result is None else int(result),
        next_run=_timestamp(_scalar(samples_by_metric, M_NEXT_RUN)),
        hosts=hosts,
    )


async def collect_run_status(source) -> RunStatus:
    """Una sola consulta instantánea; corre cada minuto."""
    return build_run_status(group_by_metric_name(await source.query(RUN_SELECTOR)))


def _next_run_line(run, now=None):
    if run.next_run is None:
        return "sin timer"
    now = now or datetime.now()
    return f"{_when(run.next_run)} (en {format_age(run.next_run - now)})"


def render_run_started(run, now=None) -> ReportView:
    fields = []
    if run.hosts:
        fields.append(
            ViewField(name="Hosts de esta corrida", value=_clip(
                "\n".join(host.line for host in run.hosts)
            ))
        )
    if run.woken_hosts:
        fields.append(
            ViewField(
                name="🔌 Encendidos por WOL",
                value=", ".join(run.woken_hosts),
                inline=True,
            )
        )
    return ReportView(
        title="🔄 Backup de la flota en curso",
        description=(
            f"Arrancó {_when(run.started)}. Los nodos apagados se encienden por "
            "WOL y vuelven a apagarse al terminar."
        ),
        color=0x3498DB,
        fields=tuple(fields),
        footer=f"Próximo backup: {_next_run_line(run, now)}",
    )


def render_run_progress(run, now=None) -> ReportView:
    """Igual que el de arranque pero con el avance: se edita el mismo mensaje."""
    view = render_run_started(run, now)
    current = run.current_host
    description = view.description
    if current:
        description = f"Respaldando **{current}**. " + description
    return ReportView(
        title=view.title,
        description=description,
        color=view.color,
        fields=view.fields,
        footer=view.footer,
    )


def render_run_finished(run, now=None) -> ReportView:
    counts = run.counts()
    severity = RESULT_SEVERITY.get(run.result, NO_DATA)
    titles = {
        RESULT_OK: "✅ Backup de la flota completado",
        RESULT_PARTIAL: "🟠 Backup de la flota parcial",
        RESULT_FAILED: "🔴 El backup de la flota falló",
    }
    fields = [
        ViewField(name="Duración", value=format_duration(run.duration), inline=True),
        ViewField(name="Terminó", value=_when(run.finished), inline=True),
        ViewField(
            name="Hosts",
            value=(
                f"{counts['ok']}/{counts['total']} ok"
                + (f" · {counts['failed']} fallidos" if counts["failed"] else "")
                + (f" · {counts['skipped']} omitidos" if counts["skipped"] else "")
            ),
            inline=True,
        ),
    ]
    if run.hosts:
        fields.append(
            ViewField(name="Detalle", value=_clip(
                "\n".join(host.line for host in run.hosts)
            ))
        )
    if run.woken_hosts:
        fields.append(
            ViewField(
                name="🔌 Encendidos por WOL",
                value=(
                    ", ".join(run.woken_hosts)
                    + " — se devuelven a su estado anterior al terminar"
                ),
            )
        )
    return ReportView(
        title=titles.get(run.result, "⚪ Corrida de backup terminada"),
        description=RESULT_LABEL.get(run.result, "resultado desconocido"),
        color=SEVERITY_COLOR[severity],
        fields=tuple(fields),
        footer=f"Próximo backup: {_next_run_line(run, now)}",
    )


@dataclass(frozen=True)
class RunAnnouncement:
    kind: str          # started | finished
    view: ReportView


class RunAnnouncer:
    """Decide qué anunciar comparando la corrida observada con lo ya anunciado.

    Guarda dos números —el arranque y el fin ya anunciados— y los persiste,
    porque el Centinela vive en pentium, que **el propio backup enciende y
    apaga**: entre el "arrancó" y el "terminó" el bot se muere. Sin persistir
    esos dos números, el aviso de fin no llega nunca o llega de nuevo en cada
    arranque del bot.

    La primera observación de todas no anuncia un final viejo: sería contar
    como novedad algo que pasó antes de que existiera este código. Una corrida
    **en curso** sí se anuncia, porque está pasando ahora.
    """

    def __init__(self, state=None):
        state = state or {}
        self.announced_started = state.get("announced_started")
        self.announced_finished = state.get("announced_finished")
        self.seeded = bool(state)

    @staticmethod
    def _epoch(moment):
        return None if moment is None else int(moment.timestamp())

    def observe(self, run, now=None):
        if not run.present:
            return []

        started = self._epoch(run.started)
        finished = self._epoch(run.finished)
        announcements = []

        if not self.seeded:
            # Adoptar lo que ya había sin anunciarlo, salvo que haya algo vivo.
            self.seeded = True
            self.announced_finished = finished
            if not run.running:
                self.announced_started = started
                return []

        if run.running and started and started != self.announced_started:
            self.announced_started = started
            announcements.append(RunAnnouncement("started", render_run_started(run, now)))

        if not run.running and finished and finished != self.announced_finished:
            self.announced_finished = finished
            # Que no se anuncie después el arranque de una corrida ya terminada.
            self.announced_started = started
            announcements.append(RunAnnouncement("finished", render_run_finished(run, now)))

        return announcements

    def dump(self) -> dict:
        return {
            "announced_started": self.announced_started,
            "announced_finished": self.announced_finished,
        }


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
