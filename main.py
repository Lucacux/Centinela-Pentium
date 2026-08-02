import discord
from discord.ext import tasks, commands
import psutil
import subprocess
import shutil
import os
import glob
import asyncio
import signal
import sys
import aiohttp
import io
from collections import deque
from datetime import datetime, timedelta
from dotenv import load_dotenv
import json
import netdiag
import procmon
import alerts
from alerts import ALARM, CRITICAL, NO_DATA, OK, WARNING, Alarm, AlarmEngine
from grafana import GrafanaClient, GrafanaError, parse_range
from fleet_report import render_fleet_pages
from ip_geolocation import CountryEstimate, CountryResolver
from remote_hosts import RemoteHostClient, RemoteHostConfig, RemoteHostError
from security_events import (
    CloudflareAccessClient,
    EventCorrelator,
    SshKeyDirectory,
    access_app_matches,
    classify_ssh_origin,
    cloudflare_event_id,
    is_loopback,
    parse_ssh_keygen_fingerprints,
    parse_timestamp,
    parse_fail2ban_banned,
    parse_fail2ban_jails,
    parse_fail2ban_log,
    parse_ssh_line,
    utcnow,
)
from ssh_baseline import CRITICAL as ANOMALY_CRITICAL, LoginBaseline
from docker_ops import (
    docker_cmd,
    get_docker_stats,
    group_services,
    list_tasks,
    resolve_service,
    restart_service,
    service_of,
)

# --- CONFIGURACION ---
load_dotenv()
TOKEN = os.getenv('DISCORD_TOKEN')
CHANNEL_ID_ENV = os.getenv('DISCORD_CHANNEL_ID')
DEBUG_MODE = os.getenv('DEBUG_MODE', 'false').lower() in ('true', '1', 'yes')
BACKUP_PATH = os.getenv('BACKUP_PATH', '')
SAFE_SUBNETS = [s.strip() for s in os.getenv('SAFE_SUBNETS', '192.168.,10.,172.').split(',')]
SERVER_NAME = os.getenv('SERVER_NAME', 'Server')
WATCHED_SERVICES = [s.strip() for s in os.getenv('WATCHED_SERVICES', '').split(',') if s.strip()]
ALLOWED_RESTART = [s.strip() for s in os.getenv('ALLOWED_RESTART', '').split(',') if s.strip()]
SSH_FAIL_THRESHOLD = int(os.getenv('SSH_FAIL_THRESHOLD', '10'))
SSH_FAIL_WINDOW = int(os.getenv('SSH_FAIL_WINDOW', '120'))
SWAP_ALERT_PCT = int(os.getenv('SWAP_ALERT_PCT', '50'))
TEMP_ALERT_C = int(os.getenv('TEMP_ALERT_C', '85'))
FAIL2BAN_ENABLED = os.getenv(
    'FAIL2BAN_ENABLED', 'true'
).lower() in ('true', '1', 'yes')
CLOUDFLARE_ACCOUNT_ID = os.getenv('CLOUDFLARE_ACCOUNT_ID', '').strip()
CLOUDFLARE_ACCESS_TOKEN = os.getenv('CLOUDFLARE_ACCESS_TOKEN', '').strip()
CLOUDFLARE_ACCESS_APP = os.getenv('CLOUDFLARE_ACCESS_APP', '').strip().lower()
CLOUDFLARE_CORRELATION_SECONDS = int(
    os.getenv('CLOUDFLARE_CORRELATION_SECONDS', '180')
)
GEOIP_COUNTRY_DB = os.getenv('GEOIP_COUNTRY_DB', '').strip()
GEOIP_COUNTRY_LOCALE = os.getenv('GEOIP_COUNTRY_LOCALE', 'es').strip()
REMOTE_ARCH_TEMP_ALERT_C = int(os.getenv('REMOTE_ARCH_TEMP_ALERT_C', '85'))
REMOTE_ARCH_SWAP_ALERT_PCT = int(os.getenv('REMOTE_ARCH_SWAP_ALERT_PCT', '50'))
REMOTE_ARCH_SSH_FAIL_THRESHOLD = int(
    os.getenv('REMOTE_ARCH_SSH_FAIL_THRESHOLD', str(SSH_FAIL_THRESHOLD))
)
REMOTE_ARCH_SSH_FAIL_WINDOW = int(
    os.getenv('REMOTE_ARCH_SSH_FAIL_WINDOW', str(SSH_FAIL_WINDOW))
)

# --- IDENTIDAD DE CLAVES SSH ---
# sshd escribe el fingerprint de la clave aceptada en cada login (LogLevel
# INFO, sin necesidad de VERBOSE). Traducirlo a un nombre es lo que convierte
# "entro luca desde 192.168.2.40" en "entro el bot de Ansible": el usuario Unix
# y la IP son iguales para varias automatizaciones, el fingerprint no.
#
# Los authorized_keys locales se listan explicitamente porque el servicio corre
# con ProtectHome=yes; cada archivo necesita su BindReadOnlyPaths en el
# drop-in de hardening (ver deploy/discord-bot-hardening.conf).
def _parse_key_files(raw):
    """``usuario:/ruta`` o ``/ruta`` (el usuario se deduce del directorio)."""
    entries = []
    for item in str(raw or '').split(','):
        item = item.strip()
        if not item:
            continue
        if ':' in item and not item.startswith('/'):
            user, _, path = item.partition(':')
        else:
            path = item
            parts = os.path.normpath(path).split(os.sep)
            user = parts[2] if len(parts) > 3 and parts[1] == 'home' else (
                'root' if path.startswith('/root/') else ''
            )
        entries.append((user.strip(), path.strip()))
    return entries


def _parse_key_labels(raw):
    """``SHA256:xxx=Ansible,SHA256:yyy=Dokploy``."""
    labels = {}
    for item in str(raw or '').split(','):
        fingerprint, _, label = item.partition('=')
        if fingerprint.strip() and label.strip():
            labels[fingerprint.strip()] = label.strip()
    return labels


SSH_KEY_FILES = _parse_key_files(os.getenv('SSH_KEY_DIRECTORY_FILES', ''))
SSH_KEY_LABELS = _parse_key_labels(os.getenv('SSH_KEY_LABELS', ''))
REMOTE_SSH_KEY_LABELS = _parse_key_labels(
    os.getenv('REMOTE_ARCH_SSH_KEY_LABELS', '')
)
SSH_KEY_REFRESH_MIN = max(5, int(os.getenv('SSH_KEY_REFRESH_MINUTES', '30')))
# Cada cuanto se puede repetir el aviso de fallos para una misma IP. Sin esto
# un escaneo de 500 intentos son 500 embeds.
SSH_FAIL_NOTIFY_COOLDOWN = timedelta(
    minutes=max(1, int(os.getenv('SSH_FAIL_NOTIFY_COOLDOWN_MIN', '15')))
)
SSH_FAIL_NOTIFY_ENABLED = os.getenv(
    'SSH_FAIL_NOTIFY_ENABLED', 'true'
).lower() in ('true', '1', 'yes')
_STATE_DIR = (
    os.getenv('STATE_DIRECTORY', '').split(':')[0]
    or os.path.expanduser('~/.local/state/centinela')
)
SSH_BASELINE_PATH = os.getenv(
    'SSH_BASELINE_PATH', os.path.join(_STATE_DIR, 'ssh-baseline.json')
)
SSH_ANOMALY_ENABLED = os.getenv(
    'SSH_ANOMALY_ENABLED', 'true'
).lower() in ('true', '1', 'yes')

# --- DIAGNOSTICO DE RED (ver netdiag.py) ---
# El Centinela aca solo OBSERVA: diagnostica y reporta. Quien reinicia el ONU es
# el ISP Uplink Guardian; nosotros lo consultamos de solo lectura.
SPEEDTEST_ENABLED = os.getenv('SPEEDTEST_ENABLED', 'true').lower() in ('true', '1', 'yes')
SPEEDTEST_EVERY_H = int(os.getenv('SPEEDTEST_EVERY_HOURS', '6'))
# Cada corrida consume ~40 MB y tarda ~25s: sin cooldown propio un usuario
# impaciente puede saturar el enlace que justamente esta tratando de medir.
SPEEDTEST_COOLDOWN = timedelta(minutes=int(os.getenv('SPEEDTEST_COOLDOWN_MIN', '10')))
SPEEDTEST_HISTORY = os.getenv('SPEEDTEST_HISTORY_FILE', 'speedtest_history.json')
SPEEDTEST_HISTORY_MAX = 60

# --- GRAFANA (feature opcional: paneles del dashboard en el bot) ---
# Todo se descubre en caliente via la API; no se hardcodea ningun dashboard/panel.
GRAFANA_URL = os.getenv('GRAFANA_URL', '').rstrip('/')
GRAFANA_TOKEN = os.getenv('GRAFANA_TOKEN', '')
GRAFANA_DEFAULT_RANGE = os.getenv('GRAFANA_DEFAULT_RANGE', '6h')
GRAFANA_THEME = os.getenv('GRAFANA_THEME', 'dark')
GRAFANA_TZ = os.getenv('GRAFANA_TZ', 'browser')
GRAFANA_PANEL_W = int(os.getenv('GRAFANA_PANEL_WIDTH', '1000'))
GRAFANA_PANEL_H = int(os.getenv('GRAFANA_PANEL_HEIGHT', '500'))
GRAFANA_DASH_W = int(os.getenv('GRAFANA_DASH_WIDTH', '1200'))
GRAFANA_DASH_H = int(os.getenv('GRAFANA_DASH_HEIGHT', '1400'))
GRAFANA_HTTP_TIMEOUT = int(os.getenv('GRAFANA_HTTP_TIMEOUT_SECONDS', '70'))
GRAFANA_ORANGE = 0xF46800
GRAFANA_GUARDIAN_ENABLED = os.getenv(
    'GRAFANA_GUARDIAN_ENABLED', 'true'
).lower() in ('true', '1', 'yes')
GRAFANA_GUARDIAN_DASHBOARD = os.getenv(
    'GRAFANA_GUARDIAN_DASHBOARD', 'fleet-overview'
).strip()
GRAFANA_GUARDIAN_RANGE = os.getenv(
    'GRAFANA_GUARDIAN_RANGE', '6h'
).strip()
GRAFANA_GUARDIAN_W = int(os.getenv('GRAFANA_GUARDIAN_WIDTH', '1600'))
GRAFANA_GUARDIAN_H = int(os.getenv('GRAFANA_GUARDIAN_HEIGHT', '1600'))
GRAFANA_GUARDIAN_PAGE_H = int(
    os.getenv('GRAFANA_GUARDIAN_PAGE_HEIGHT', '900')
)
GRAFANA_GUARDIAN_START_DELAY = max(0, int(
    os.getenv('GRAFANA_GUARDIAN_START_DELAY_SECONDS', '300')
))

grafana_client = (
    GrafanaClient(GRAFANA_URL, GRAFANA_TOKEN, timeout=GRAFANA_HTTP_TIMEOUT)
    if GRAFANA_URL and GRAFANA_TOKEN else None
)
cloudflare_client = (
    CloudflareAccessClient(CLOUDFLARE_ACCOUNT_ID, CLOUDFLARE_ACCESS_TOKEN)
    if CLOUDFLARE_ACCOUNT_ID and CLOUDFLARE_ACCESS_TOKEN else None
)
country_resolver = CountryResolver(
    database_path=GEOIP_COUNTRY_DB,
    locale=GEOIP_COUNTRY_LOCALE,
)
remote_arch_config = RemoteHostConfig.from_env()
remote_arch = (
    RemoteHostClient(remote_arch_config) if remote_arch_config else None
)
local_key_directory = SshKeyDirectory(SSH_KEY_LABELS)
remote_key_directory = SshKeyDirectory(REMOTE_SSH_KEY_LABELS)
login_baseline = LoginBaseline(SSH_BASELINE_PATH if SSH_ANOMALY_ENABLED else '')

if not TOKEN or not CHANNEL_ID_ENV:
    print("ERROR: Falta DISCORD_TOKEN o DISCORD_CHANNEL_ID en .env")
    sys.exit(1)

CHANNEL_ID = int(CHANNEL_ID_ENV)

# --- DETECCION DE DISTRO ---
def detect_distro():
    if shutil.which("pacman"):
        return "arch"
    if shutil.which("apt"):
        return "debian"
    return "unknown"

DISTRO = detect_distro()

if DEBUG_MODE:
    print(f"Distro detectada: {DISTRO}")

# --- CONFIGURACION DEL BOT ---
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

# --- COOLDOWN GLOBAL PARA COMANDOS ---
COMMAND_COOLDOWN = commands.CooldownMapping.from_cooldown(1, 10, commands.BucketType.user)

@bot.check
async def global_cooldown(ctx):
    bucket = COMMAND_COOLDOWN.get_bucket(ctx.message)
    retry_after = bucket.update_rate_limit()
    if retry_after:
        await ctx.send(f"⏳ Espera **{int(retry_after)}s** antes de usar otro comando.", delete_after=5)
        return False
    return True

# --- OBSERVABILIDAD ---
HISTORY_LEN = 360  # 6 horas a 1 muestra/min
history_time = deque(maxlen=HISTORY_LEN)
history_cpu = deque(maxlen=HISTORY_LEN)
history_ram = deque(maxlen=HISTORY_LEN)
history_disk = deque(maxlen=HISTORY_LEN)
history_swap = deque(maxlen=HISTORY_LEN)

stats_counter = {
    "ssh_events": 0,
    "ssh_fails": 0,
    "docker_alerts": 0,
    "service_alerts": 0,
    "fail2ban_bans": 0,
    "cloudflare_access": 0,
    "alerts": 0,
}
# Solo para lo que NO pasa por el motor de alarmas (que lleva su propio
# cooldown por alarma): fuerza bruta SSH y el ritmo del speedtest.
last_alert_time = {
    "speedtest": datetime.min,
    "slow": datetime.min,
}
# Ultimo aviso individual de fallo por IP (local y remoto en el mismo dict,
# con prefijo de nodo en la clave).
ssh_fail_notified = {}
ALERT_COOLDOWN = timedelta(hours=1)

# --- ALARMAS (ver alerts.py) ---
# Umbral, N de M, severidad y cooldown declarados en un solo lugar. Solo lo
# marcado como critico atraviesa el modo silencio nocturno.
#
# `action` describe que hacer, pero NO se ejecuta: se propone y decidis vos.
# Nada de esto toca el sistema por su cuenta.
alarm_engine = AlarmEngine([
    # 2 de 3 minutos: un pico de compilacion no es una emergencia, tres
    # minutos sostenidos al 90% si.
    Alarm("cpu", "🔥 CPU alta", 90, datapoints=2, periods=3, severity=CRITICAL,
          description="CPU sostenida por encima del 90%.",
          action="Revisá `!top`; si hay un proceso desbocado, `!restart <servicio>`."),
    Alarm("ram", "🧠 RAM alta", 90, datapoints=2, periods=3, severity=CRITICAL,
          description="Memoria por encima del 90%.",
          action="Revisá `!top`. Con 3.8 GB en el pentium, el candidato suele ser un contenedor sin límite."),
    # El disco no oscila: si esta al 91% dos muestras seguidas, esta lleno.
    Alarm("disco", "🚨 Disco crítico", 90, datapoints=2, periods=2, severity=CRITICAL,
          description="Partición raíz por encima del 90%.",
          action="`docker system prune` y revisá `/var/log`. Ya pasó de llenar `/var` en la VM Debian."),
    Alarm("swap", "⚠️ Swap en uso", SWAP_ALERT_PCT, datapoints=3, periods=4, severity=WARNING,
          description="Uso de swap sostenido: el equipo está paginando.",
          action="Ver qué proceso creció en `!top` por RAM."),
    Alarm("temp", "🌡️ Temperatura alta", TEMP_ALERT_C, datapoints=2, periods=3, severity=CRITICAL,
          unit="°C", description="Sensor por encima del umbral.",
          action="Revisá ventilación y polvo. Si el sensor desaparece, la alarma pasa a SIN DATOS."),
])
last_docker_alert = {}
docker_heal_attempts = {}
DOCKER_LOOP_COOLDOWN = timedelta(minutes=30)
HEAL_TIMEOUT = timedelta(hours=1)


last_service_status = {}
security_events = EventCorrelator(window_seconds=900)
fail2ban_banned = {}
active_ban_notifications = set()
fail2ban_journal_since = utcnow() - timedelta(minutes=2)
cloudflare_seen = set()
cloudflare_seen_order = deque(maxlen=2000)
cloudflare_claimed = set()
cloudflare_claimed_order = deque(maxlen=2000)
cloudflare_since = utcnow() - timedelta(minutes=2)
cloudflare_last_error_log = None
# Capa culpable del ultimo corte ("wan", "dns", ...) o None si la red esta sana.
# Guardar la CAPA y no un bool permite avisar cuando la falla se MUEVE de lugar
# (p.ej. vuelve la WAN pero ahora lo roto es el DNS): con un bool eso pasaba
# desapercibido porque "seguia caido".
network_down_layer = None
network_down_since = None
speedtest_running = False

# --- NODO ARCH REMOTO ---
# El agente remoto no es otro bot de Discord: es un colector de operaciones
# fijas, invocado mediante una clave SSH con forced-command y sin shell.
remote_history_time = deque(maxlen=HISTORY_LEN)
remote_history_cpu = deque(maxlen=HISTORY_LEN)
remote_history_ram = deque(maxlen=HISTORY_LEN)
remote_history_disk = deque(maxlen=HISTORY_LEN)
remote_history_swap = deque(maxlen=HISTORY_LEN)
remote_last_snapshot = None
remote_consecutive_failures = 0
remote_down_since = None
remote_last_service_status = {}
remote_network_down_since = None
remote_security_events = EventCorrelator(window_seconds=900)
remote_security_since = utcnow() - timedelta(minutes=2)
remote_security_seen = set()
remote_security_seen_order = deque(maxlen=4000)
remote_last_alert_time = {}
remote_last_docker_alert = {}
remote_docker_heal_attempts = {}
remote_backup_alerted = False
remote_stats_counter = {
    "ssh_events": 0,
    "ssh_fails": 0,
    "docker_alerts": 0,
    "service_alerts": 0,
    "fail2ban_bans": 0,
    "agent_failures": 0,
}


def _remote_alarm_engine():
    host = remote_arch_config.name if remote_arch_config else "Arch"
    return AlarmEngine([
        Alarm(
            "cpu", f"🔥 CPU alta — {host}", 90,
            datapoints=2, periods=3, severity=CRITICAL,
            description="CPU remota sostenida por encima del 90%.",
            action="Revisá `!top arch`.",
        ),
        Alarm(
            "ram", f"🧠 RAM alta — {host}", 90,
            datapoints=2, periods=3, severity=CRITICAL,
            description="Memoria remota por encima del 90%.",
            action="Revisá `!top arch`.",
        ),
        Alarm(
            "disco", f"🚨 Disco crítico — {host}", 90,
            datapoints=2, periods=2, severity=CRITICAL,
            description="Partición raíz remota por encima del 90%.",
            action="Revisá el consumo de disco en el nodo Arch.",
        ),
        Alarm(
            "swap", f"⚠️ Swap en uso — {host}",
            REMOTE_ARCH_SWAP_ALERT_PCT,
            datapoints=3, periods=4, severity=WARNING,
            description="Uso de swap remoto sostenido.",
            action="Revisá `!top arch` por RAM.",
        ),
        Alarm(
            "temp", f"🌡️ Temperatura alta — {host}",
            REMOTE_ARCH_TEMP_ALERT_C,
            datapoints=2, periods=3, severity=CRITICAL, unit="°C",
            description="Sensor remoto por encima del umbral.",
            action="Revisá ventilación y sensores con `!temps arch`.",
        ),
    ])


remote_alarm_engine = _remote_alarm_engine()

# ==========================================
# HELPERS VISUALES
# ==========================================
def _country_from_event(event):
    if event is None:
        return None
    label = str(event.metadata.get("country") or "")
    if label:
        return CountryEstimate(
            name=label,
            source=str(event.metadata.get("country_source") or ""),
        )
    return country_resolver.resolve(event.ip)


def _add_country_field(embed, country):
    if country is None:
        return
    if country.source == "DB-IP Lite local":
        source = "\nFuente: [DB-IP Lite](https://db-ip.com) local"
    else:
        source = f"\nFuente: `{country.source}`" if country.source else ""
    embed.add_field(
        name="🌍 País estimado por IP",
        value=f"`{country.label}`{source}",
        inline=True,
    )


def _remember_bounded(value, members, order):
    if value in members:
        return False
    if len(order) == order.maxlen:
        members.discard(order.popleft())
    members.add(value)
    order.append(value)
    return True


def _claim_cloudflare_event(event):
    event_id = str(event.metadata.get("event_id") or "") if event else ""
    if not event_id:
        return False
    return _remember_bounded(
        event_id, cloudflare_claimed, cloudflare_claimed_order
    )


def _cloudflare_correlation_note(status, origin_ip):
    prefix = f"`sshd` recibió `{origin_ip}` desde el proxy local. "
    if status == "missing_app":
        return (
            prefix
            + "La API está configurada, pero falta `CLOUDFLARE_ACCESS_APP`; "
            "no se correlaciona entre aplicaciones por seguridad."
        )
    if status == "api_error":
        return (
            prefix
            + "La consulta de Access falló; se conservó la IP observada para "
            "no atribuir una IP pública sin evidencia."
        )
    if status == "not_found":
        return (
            prefix
            + "La API fue consultada, pero no apareció un acceso autorizado "
            f"para la aplicación dentro de ±{CLOUDFLARE_CORRELATION_SECONDS}s."
        )
    return (
        prefix
        + "La IP pública, el usuario de Access y el Ray ID no están "
        "disponibles hasta configurar la API de Access."
    )


def _ingest_cloudflare_item(item):
    """Add one matching API item once and return its event plus country."""
    global cloudflare_since
    item_timestamp = parse_timestamp(item.get("created_at"))
    if item_timestamp > cloudflare_since:
        cloudflare_since = item_timestamp

    app_domain = str(item.get("app_domain") or "")
    if not access_app_matches(CLOUDFLARE_ACCESS_APP, app_domain):
        return None
    event_id = cloudflare_event_id(item)
    if not _remember_bounded(
        event_id, cloudflare_seen, cloudflare_seen_order
    ):
        return None

    access_ip = str(item.get("ip_address") or "")
    country = country_resolver.resolve(access_ip, cloudflare_item=item)
    event = security_events.add(
        "cloudflare_access",
        ip=access_ip,
        user=str(item.get("user_email") or ""),
        timestamp=item.get("created_at"),
        allowed=bool(item.get("allowed")),
        event_id=event_id,
        ray_id=str(item.get("ray_id") or ""),
        app_domain=app_domain,
        action=str(item.get("action") or ""),
        country=country.label if country else "",
        country_source=country.source if country else "",
    )
    stats_counter["cloudflare_access"] += 1
    return event, country


async def _notify_cloudflare_access(channel, event, country):
    allowed = event.metadata["allowed"]
    embed = discord.Embed(
        title=(
            "☁️ Cloudflare Access autorizado"
            if allowed else "🚫 Cloudflare Access denegado"
        ),
        color=0x2ecc71 if allowed else 0xe74c3c,
        timestamp=datetime.now(),
    )
    embed.add_field(
        name="👤 Identidad",
        value=f"`{event.user or 'desconocida'}`",
        inline=True,
    )
    embed.add_field(
        name="🌐 IP pública observada",
        value=f"`{event.ip or 'desconocida'}`",
        inline=True,
    )
    _add_country_field(embed, country)
    embed.add_field(
        name="🎯 Aplicación",
        value=f"`{event.metadata['app_domain'] or 'desconocida'}`",
        inline=False,
    )
    embed.add_field(
        name="🔎 Trazabilidad",
        value=(
            f"Ray `{event.metadata['ray_id'] or '?'}` · "
            f"acción `{event.metadata['action'] or '?'}`"
        ),
        inline=False,
    )
    await channel.send(embed=embed)


def _log_cloudflare_error(error):
    global cloudflare_last_error_log
    now = utcnow()
    if (
        cloudflare_last_error_log is None
        or now - cloudflare_last_error_log >= timedelta(minutes=5)
    ):
        print(f"Cloudflare Access API: {error}", file=sys.stderr)
        cloudflare_last_error_log = now


async def _refresh_cloudflare_access(channel, since):
    try:
        items = await cloudflare_client.fetch(since)
    except Exception as error:
        _log_cloudflare_error(error)
        return False
    for item in sorted(items, key=lambda value: value.get("created_at", "")):
        ingested = _ingest_cloudflare_item(item)
        if ingested is not None:
            await _notify_cloudflare_access(channel, *ingested)
    return True


async def _correlate_cloudflare_login(channel, timestamp):
    """Query Access on demand, then atomically claim the closest event."""
    if cloudflare_client is None:
        return None, "unconfigured"
    if not CLOUDFLARE_ACCESS_APP:
        return None, "missing_app"

    successful_query = False
    for delay in (0, 2, 5):
        if delay:
            await asyncio.sleep(delay)
        event = security_events.nearest_cloudflare_access(
            at=timestamp,
            max_skew_seconds=CLOUDFLARE_CORRELATION_SECONDS,
            app_domain=CLOUDFLARE_ACCESS_APP,
            excluded_ids=cloudflare_claimed,
        )
        if event is not None and _claim_cloudflare_event(event):
            return event, "matched"
        since = timestamp - timedelta(seconds=CLOUDFLARE_CORRELATION_SECONDS)
        successful_query = (
            await _refresh_cloudflare_access(channel, since)
            or successful_query
        )

    event = security_events.nearest_cloudflare_access(
        at=timestamp,
        max_skew_seconds=CLOUDFLARE_CORRELATION_SECONDS,
        app_domain=CLOUDFLARE_ACCESS_APP,
        excluded_ids=cloudflare_claimed,
    )
    if event is not None and _claim_cloudflare_event(event):
        return event, "matched"
    return None, "not_found" if successful_query else "api_error"


def make_bar(value, length=12):
    pct = max(0.0, min(100.0, float(value)))
    filled = round(pct / 100 * length)
    bar = chr(9608) * filled + chr(9617) * (length - filled)
    if pct >= 90:
        emoji = "🔴"
    elif pct >= 70:
        emoji = "🟡"
    else:
        emoji = "🟢"
    return f"{emoji} `{bar}` **{int(pct)}%**"

def _fmt_dur(segundos):
    if not segundos:
        return "un momento"
    m, s = divmod(int(segundos), 60)
    h, m = divmod(m, 60)
    return f"{h}h {m}m" if h else (f"{m}m {s}s" if m else f"{s}s")


def build_alarm_embed(evento, temps=None, swap=None):
    """Convierte un evento del motor en el embed que se postea.

    Aca vive el "si pasa A, respondemos con B": cada alarma trae su accion
    sugerida y el contexto que hace falta para decidir. La accion se PROPONE,
    nunca se ejecuta sola.
    """
    alarma = evento["alarm"]
    valor, estado = evento["value"], evento["to"]

    if estado == OK:
        embed = discord.Embed(
            title=f"✅ Normalizado: {alarma.title}",
            description=f"Volvió a la normalidad tras **{_fmt_dur(evento['duration_s'])}** en alarma.",
            color=0x2ecc71,
        )
        if valor is not None:
            embed.add_field(name="Valor actual", value=f"{valor:.1f}{alarma.unit}", inline=True)
        return embed

    if estado == NO_DATA:
        # No es lo mismo que "todo bien": se dejo de poder medir.
        return discord.Embed(
            title=f"❔ Sin datos: {alarma.title}",
            description=f"{alarma.description}\n\nLa métrica dejó de poder medirse. No es lo mismo que estar en cero.",
            color=0x95a5a6,
        )

    reincidencia = evento["kind"] == "reminder"
    embed = discord.Embed(
        title=f"{alarma.title}{' (sigue)' if reincidencia else ''}",
        description=alarma.description,
        color=0xff0000 if alarma.severity == CRITICAL else 0xe67e22,
    )
    if valor is not None:
        embed.add_field(
            name="Valor",
            value=f"**{valor:.1f}{alarma.unit}** (umbral {alarma.threshold}{alarma.unit})\n"
                  + (make_bar(valor) if alarma.unit == "%" else ""),
            inline=False,
        )
    embed.add_field(
        name="Criterio",
        value=f"{alarma.datapoints} de {alarma.periods} muestras en falta · severidad **{alarma.severity}**",
        inline=False,
    )
    if reincidencia and evento["duration_s"]:
        embed.add_field(name="En alarma desde hace", value=_fmt_dur(evento["duration_s"]), inline=False)

    # Contexto util segun la metrica: para CPU y RAM, quien lo esta causando.
    # Sale del sampler cacheado, que ya tiene tasas reales medidas en el ultimo
    # minuto -- antes esto listaba systemd y kthreadd con 0%.
    if alarma.name in ("cpu", "ram", "swap"):
        clave = "cpu" if alarma.name == "cpu" else "mem"
        if procmon.sampler.warm():
            filas = procmon.format_top(procmon.sampler.top(3, clave), clave)
            if filas:
                embed.add_field(name="Top procesos", value=filas, inline=False)
        else:
            embed.add_field(
                name="Top procesos",
                value="_Todavía sin muestra válida de procesos._",
                inline=False,
            )
    if alarma.name == "temp" and temps:
        caliente = max(temps, key=temps.get)
        embed.add_field(name="Sensor más caliente", value=f"`{caliente}` — {temps[caliente]:.0f}°C", inline=False)
    if alarma.name == "swap" and swap is not None:
        embed.add_field(name="Swap usado", value=format_bytes(swap.used), inline=True)

    if alarma.action:
        embed.add_field(name="💡 Sugerencia", value=alarma.action, inline=False)
    embed.set_footer(text=evento["at"].strftime('%d/%m/%Y %H:%M:%S'))
    return embed


def health_color(score):
    if score >= 80:
        return 0x2ecc71
    if score >= 50:
        return 0xf1c40f
    return 0xe74c3c

def health_emoji(score):
    if score >= 80:
        return "🟢"
    if score >= 50:
        return "🟡"
    return "🔴"

def predict_resource(history_deque):
    if len(history_deque) < 10:
        return "Estable"
    recent = list(history_deque)
    diff = recent[-1] - recent[0]
    if diff > 0.5:
        remaining = 100 - recent[-1]
        rate_per_sample = diff / len(recent)
        if rate_per_sample <= 0:
            return "Estable"
        samples_left = remaining / rate_per_sample
        hours = samples_left / 60
        if hours < 1:
            return f"Lleno en {int(samples_left)}min"
        if hours < 24:
            return f"Lleno en {int(hours)}h"
        return f"Lleno en {int(hours / 24)}d"
    elif diff < -0.5:
        return "Liberando"
    return "Estable"

def format_bytes(b):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"

# ==========================================
# HELPERS DE PAQUETES (MULTI-DISTRO)
# ==========================================
def parse_updates_debian(raw_output):
    updates = []
    for line in raw_output.splitlines():
        if '/' not in line or '[upgradable from:' not in line:
            continue
        try:
            pkg_name = line.split('/')[0]
            new_ver = line.split()[1]
            old_ver = line.split('[upgradable from:')[1].rstrip(']').strip()
            updates.append((pkg_name, old_ver, new_ver))
        except (IndexError, ValueError):
            continue
    return updates

def parse_updates_arch(raw_output):
    updates = []
    for line in raw_output.splitlines():
        line = line.strip()
        if not line or '->' not in line:
            continue
        try:
            parts = line.split()
            pkg_name = parts[0]
            old_ver = parts[1]
            new_ver = parts[3] if len(parts) >= 4 else "?"
            updates.append((pkg_name, old_ver, new_ver))
        except (IndexError, ValueError):
            continue
    return updates

async def fetch_updates():
    if DISTRO == "arch":
        await asyncio.to_thread(subprocess.getoutput, "pacman -Sy --noconfirm 2>/dev/null")
        raw = await asyncio.to_thread(subprocess.getoutput, "pacman -Qu 2>/dev/null")
        return parse_updates_arch(raw)
    elif DISTRO == "debian":
        await asyncio.to_thread(subprocess.getoutput, "apt-get update -qq 2>/dev/null")
        raw = await asyncio.to_thread(subprocess.getoutput, "apt list --upgradable 2>/dev/null")
        return parse_updates_debian(raw)
    return []

# NOTA: el escaneo de CVEs (arch-audit / debsecan) vivia aca y se fue junto con
# el comando !cve. Lo cubre el Updates-Bot con `!cve host <nodo>`, que ademas
# distingue "hay fix publicado" de "un update lo cierra" — distincion que esta
# version cruda no hacia, y que es la diferencia entre un alerta accionable y
# 38 Critical permanentes que nadie puede arreglar.

# ==========================================
# HELPERS DE SISTEMA
# ==========================================
def get_temperatures():
    temps = {}
    try:
        sensor_temps = psutil.sensors_temperatures()
        if not sensor_temps:
            return temps
        for chip, entries in sensor_temps.items():
            for entry in entries:
                label = entry.label or chip
                temps[label] = entry.current
    except (AttributeError, Exception):
        pass
    return temps

def get_open_ports():
    ports = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == 'LISTEN':
            try:
                proc = psutil.Process(conn.pid) if conn.pid else None
                name = proc.name() if proc else "?"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                name = "?"
            ports.append({
                "port": conn.laddr.port,
                "ip": conn.laddr.ip,
                "pid": conn.pid or 0,
                "process": name
            })
    seen = set()
    unique = []
    for p in sorted(ports, key=lambda x: x["port"]):
        if p["port"] not in seen:
            seen.add(p["port"])
            unique.append(p)
    return unique

def get_active_sessions():
    sessions = []
    try:
        for u in psutil.users():
            sessions.append({
                "user": u.name,
                "terminal": u.terminal or "?",
                "host": u.host or "local",
                "started": datetime.fromtimestamp(u.started).strftime('%d/%m %H:%M')
            })
    except Exception:
        pass
    return sessions

def get_smart_health():
    if not shutil.which("smartctl"):
        return None
    for disk in ["/dev/sda", "/dev/nvme0n1", "/dev/nvme0", "/dev/vda"]:
        if os.path.exists(disk):
            try:
                result = subprocess.run(
                    ["smartctl", "-H", "-A", disk],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
            except (OSError, subprocess.SubprocessError):
                return {"disk": disk, "output": "smartctl no disponible"}
            return {"disk": disk, "output": result.stdout.strip()}
    return None

def get_service_status(service_name):
    try:
        result = subprocess.run(
            ["systemctl", "is-active", service_name],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return result.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def get_service_logs(service_name, lines=5):
    try:
        result = subprocess.run(
            ["journalctl", "-u", service_name, "-n", str(lines), "--no-pager"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        return result.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""

# ==========================================
# HELPER BACKUP BORG
# ==========================================
def get_borg_last_backup(repo_path):
    """Devuelve (mtime: datetime, index_file: str) del index.* mas reciente en el repo Borg."""
    candidates = glob.glob(os.path.join(repo_path, "index.*"))
    if not candidates:
        return None, None
    newest = max(candidates, key=os.path.getmtime)
    mtime = datetime.fromtimestamp(os.path.getmtime(newest))
    return mtime, newest

# ==========================================
# IDENTIDAD DE CLAVES SSH
# ==========================================
def _read_local_key_directory():
    """Fingerprints de los authorized_keys declarados en el entorno.

    Se invoca `ssh-keygen -lf` en vez de parsear el archivo a mano porque
    calcular el fingerprint implica decodificar el blob base64 y hashearlo con
    el mismo formato que usa sshd; delegarlo evita que un formato de clave
    nuevo (o un `cert-authority`) devuelva un hash que no matchea el del log.
    """
    entries = []
    covered = []
    for user, path in SSH_KEY_FILES:
        if not path or not os.path.isfile(path):
            continue
        try:
            result = subprocess.run(
                ["ssh-keygen", "-lf", path],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue
        for entry in parse_ssh_keygen_fingerprints(result.stdout):
            entry["user"] = user
            entries.append(entry)
        if user:
            covered.append(user)
    return entries, covered


def _load_remote_key_entries(payload):
    """Convierte la respuesta cruda de la accion `keys` del agente."""
    entries = []
    for item in (payload or {}).get("entries") or []:
        if not isinstance(item, dict):
            continue
        for entry in parse_ssh_keygen_fingerprints(item.get("line", "")):
            entry["user"] = str(item.get("user") or "")
            entries.append(entry)
    return entries, [
        str(user) for user in (payload or {}).get("covered_users") or []
    ]


def _key_identity_field(directory, event):
    """Campo 'Clave' del embed: quien es, no solo que hash uso.

    Devuelve ``(texto, reconocida)``. El fingerprint completo nunca entra al
    embed: 12 caracteres alcanzan para distinguir las claves de una flota y
    mantienen el mensaje legible en el celular.
    """
    fingerprint = str(event.get("fingerprint") or "")
    method = str(event.get("method") or "")
    if not fingerprint:
        if method and method != "publickey":
            return f"Sin clave · autenticacion `{method}`", False
        return "sshd no registro el fingerprint", False
    label, known = directory.describe(fingerprint)
    short = directory.short(fingerprint)
    key_type = str(event.get("key_type") or "").upper()
    suffix = f" · `{key_type}` `…{short}`" if key_type else f" · `…{short}`"
    if known:
        return f"**{label}**{suffix}", True
    return f"⚠️ **Clave no reconocida**{suffix}", False


def _anomaly_field(verdict):
    if not verdict or not verdict.reasons:
        return None
    return "\n".join(f"• {reason['text']}" for reason in verdict.reasons)


def _assess_login(node, event, directory, timestamp):
    """Evalua contra la linea base y luego incorpora el login al perfil.

    El orden importa: `assess` primero, `observe` despues. Al reves, todo
    login seria conocido por construccion y la deteccion no serviria de nada.
    """
    if not SSH_ANOMALY_ENABLED:
        return None
    if not login_baseline.loaded:
        login_baseline.load()
    verdict = login_baseline.assess(node, event, directory, now=timestamp)
    login_baseline.observe(node, event, now=timestamp)
    login_baseline.prune(now=timestamp)
    if not login_baseline.save() and DEBUG_MODE:
        print(
            f"No se pudo persistir la linea base en {SSH_BASELINE_PATH}",
            file=sys.stderr,
        )
    return verdict


def _build_ssh_fail_embed(event, summary, *, node="", title_prefix=""):
    """Embed de un intento fallido, ya agregado por IP.

    Un fallo suelto no es una alerta y tampoco es ruido: la diferencia esta en
    contra QUE cuenta se intento. sshd distingue explicitamente "invalid user"
    (la cuenta no existe: escaneo generico de Internet) de un fallo contra una
    cuenta real, que significa que alguien sabe a quien apuntarle. Solo el
    segundo caso merece color rojo.
    """
    ip = event.get("ip") or "desconocida"
    user = event.get("user") or "?"
    invalid = bool(event.get("invalid_user"))
    external = not any(
        str(ip).startswith(prefix) for prefix in SAFE_SUBNETS if prefix
    ) and not is_loopback(ip)
    serious = not invalid
    embed = discord.Embed(
        title=(
            f"{title_prefix}⚠️ Intento de login fallido"
            if serious
            else f"{title_prefix}👣 Sondeo SSH rechazado"
        ),
        description=(
            f"Cuenta **inexistente** `{user}`: patron de escaneo automatico."
            if invalid
            else f"Fallo la autenticacion de la cuenta real `{user}`."
        ),
        color=0xe67e22 if serious else 0x95a5a6,
    )
    embed.add_field(name="🌐 IP", value=f"`{ip}`", inline=True)
    embed.add_field(
        name="🔁 En la ventana",
        value=f"{summary.get('ssh_fails', 1)} intento(s)",
        inline=True,
    )
    method = str(event.get("method") or "")
    if method and method != "none":
        embed.add_field(name="🔑 Metodo", value=f"`{method}`", inline=True)
    if external:
        embed.add_field(
            name="🏠 Origen", value="⚠️ Fuera de la red local", inline=True
        )
    users = summary.get("users") or []
    if len(users) > 1:
        embed.add_field(
            name="👥 Cuentas probadas",
            value=", ".join(f"`{item}`" for item in users[:10]),
            inline=False,
        )
    if node:
        embed.set_footer(text=f"Nodo: {node}")
    return embed


def _should_notify_fail(store, key, now, cooldown=SSH_FAIL_NOTIFY_COOLDOWN):
    if now - store.get(key, datetime.min) < cooldown:
        return False
    store[key] = now
    return True


@tasks.loop(minutes=SSH_KEY_REFRESH_MIN)
async def refresh_key_directories():
    """Relee los authorized_keys, local y remoto.

    Periodico y no una sola vez al arrancar: agregar una clave nueva no
    deberia exigir reiniciar el bot para que deje de reportarse como
    desconocida.
    """
    entries, covered = await asyncio.to_thread(_read_local_key_directory)
    local_key_directory.load(entries, covered_users=covered)
    if remote_arch is None:
        return
    try:
        payload = await remote_arch.request("keys")
    except RemoteHostError as error:
        if DEBUG_MODE:
            print(f"No se pudo leer el directorio de claves remoto: {error}",
                  file=sys.stderr)
        return
    remote_entries, remote_covered = _load_remote_key_entries(payload)
    remote_key_directory.load(remote_entries, covered_users=remote_covered)


# ==========================================
# SSH WATCHER (MULTI-DISTRO)
# ==========================================
async def watch_ssh_logs():
    await bot.wait_until_ready()
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return
    if DISTRO == "arch" or not os.path.exists(os.getenv('SSH_LOG_FILE', '/var/log/auth.log')):
        await _watch_ssh_journalctl(channel)
    else:
        await _watch_ssh_file(channel, os.getenv('SSH_LOG_FILE', '/var/log/auth.log'))

async def _watch_ssh_journalctl(channel):
    try:
        proc = await asyncio.create_subprocess_exec(
            "journalctl", "-fu", "ssh", "-n", "0", "--no-pager",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
        )
    except Exception as e:
        if DEBUG_MODE:
            print(f"No se pudo iniciar journalctl: {e}")
        return
    try:
        while not bot.is_closed():
            line = await proc.stdout.readline()
            if not line:
                await asyncio.sleep(1)
                continue
            decoded = line.decode('utf-8', errors='ignore')
            if "Accepted" in decoded:
                await _process_ssh_login(channel, decoded)
            elif "Failed password" in decoded or "authentication failure" in decoded.lower():
                await _process_ssh_fail(channel, decoded)
    finally:
        proc.kill()

async def _watch_ssh_file(channel, log_file):
    try:
        f = open(log_file, 'r')
        f.seek(0, 2)
    except Exception as e:
        if DEBUG_MODE:
            print(f"No se pudo abrir {log_file}: {e}")
        return
    try:
        while not bot.is_closed():
            line = f.readline()
            if not line:
                await asyncio.sleep(1)
                continue
            if "sshd" in line:
                if "Accepted" in line:
                    await _process_ssh_login(channel, line)
                elif "Failed password" in line or "authentication failure" in line.lower():
                    await _process_ssh_fail(channel, line)
    finally:
        f.close()

async def _process_ssh_login(channel, line):
    stats_counter["ssh_events"] += 1
    event = parse_ssh_line(line)
    if not event:
        return
    user = event["user"]
    origin_ip = event["ip"]
    timestamp = utcnow()
    cf_event = None
    correlation_status = "direct"
    if is_loopback(origin_ip):
        cf_event, correlation_status = await _correlate_cloudflare_login(
            channel, timestamp
        )
    real_ip = cf_event.ip if cf_event else origin_ip
    country = (
        _country_from_event(cf_event)
        if cf_event else country_resolver.resolve(real_ip)
    )
    security_events.add(
        "ssh_login",
        ip=real_ip,
        user=user,
        timestamp=timestamp,
        transport_ip=origin_ip,
        cloudflare_ray=cf_event.metadata.get("ray_id") if cf_event else "",
        cloudflare_correlation=correlation_status,
        country=country.label if country else "",
        country_source=country.source if country else "",
    )
    origin = classify_ssh_origin(
        origin_ip,
        real_ip,
        SAFE_SUBNETS,
        correlated=cf_event is not None,
    )
    identity, recognized = _key_identity_field(local_key_directory, event)
    verdict = _assess_login(SERVER_NAME, event, local_key_directory, timestamp)
    suspicious = bool(verdict and verdict.suspicious)
    embed = discord.Embed(
        title="🚨 Login SSH sospechoso" if suspicious else "🔑 Nuevo Login SSH",
        color=(
            0xff0000
            if suspicious
            else (
                0xf1c40f
                if origin["unresolved_proxy"] or not recognized
                else (0x2ecc71 if origin["is_local"] else 0xe67e22)
            )
        ),
    )
    embed.add_field(name="👤 Usuario", value=f"`{user}`", inline=True)
    embed.add_field(
        name="🌐 IP pública (Cloudflare)" if cf_event else "🌐 IP observada",
        value=f"`{real_ip}`",
        inline=True,
    )
    embed.add_field(
        name="🏠 Origen",
        value=origin["label"],
        inline=True,
    )
    embed.add_field(name="🔐 Clave", value=identity, inline=False)
    anomalies = _anomaly_field(verdict)
    if anomalies:
        embed.add_field(
            name="🚩 Anomalías" if suspicious else "ℹ️ Notas",
            value=anomalies,
            inline=False,
        )
    if cf_event:
        embed.add_field(
            name="☁️ Cloudflare Access",
            value=(
                f"`{cf_event.user or 'usuario desconocido'}` · "
                f"Ray `{cf_event.metadata.get('ray_id') or '?'}`\n"
                f"Correlación temporal ({CLOUDFLARE_CORRELATION_SECONDS}s); "
                f"sshd vio `{origin_ip}`."
            ),
            inline=False,
        )
    elif origin["unresolved_proxy"]:
        embed.add_field(
            name="☁️ Cloudflare Access",
            value=_cloudflare_correlation_note(
                correlation_status, origin_ip
            ),
            inline=False,
        )
    _add_country_field(embed, country)
    embed.set_footer(text=datetime.now().strftime('%H:%M:%S'))
    await channel.send(embed=embed)

async def _process_ssh_fail(channel, line):
    stats_counter["ssh_fails"] += 1
    now = datetime.now()
    event = parse_ssh_line(line)
    ip = event["ip"] if event else "desconocida"
    user = event["user"] if event else ""
    security_events.add("ssh_fail", ip=ip, user=user)

    summary = security_events.summarize_ip(
        ip, max_age_seconds=SSH_FAIL_WINDOW
    )
    recent_fails = summary["ssh_fails"]
    alert_key = f"bruteforce:{ip}"
    # Por debajo del umbral de fuerza bruta se avisa igual, pero acotado por
    # IP: es la unica forma de enterarse de un intento aislado contra una
    # cuenta real, que es justo el caso que el umbral nunca alcanza.
    if (
        SSH_FAIL_NOTIFY_ENABLED
        and event
        and recent_fails < SSH_FAIL_THRESHOLD
        and _should_notify_fail(ssh_fail_notified, f"local:{ip}", now)
    ):
        await channel.send(
            embed=_build_ssh_fail_embed(event, summary, node=SERVER_NAME)
        )
    if (
        recent_fails >= SSH_FAIL_THRESHOLD
        and now - last_alert_time.get(alert_key, datetime.min) > ALERT_COOLDOWN
    ):
        embed = discord.Embed(
            title="🚨 Posible Brute Force SSH",
            description=(
                f"**{recent_fails} intentos fallidos correlacionados** "
                f"desde la misma IP."
            ),
            color=0xff0000
        )
        embed.add_field(name="🌐 Ultima IP", value=f"`{ip}`", inline=True)
        _add_country_field(embed, country_resolver.resolve(ip))
        if summary["users"]:
            embed.add_field(
                name="👥 Usuarios probados",
                value=", ".join(f"`{item}`" for item in summary["users"][:10]),
                inline=True,
            )
        embed.add_field(name="🛡 Recomendacion", value="Revisar fail2ban / firewall", inline=True)
        embed.set_footer(text=now.strftime('%H:%M:%S'))
        await channel.send(embed=embed)
        last_alert_time[alert_key] = now

# ==========================================
# GENERADOR DE GRAFICOS
# ==========================================
async def get_chart_image(include_disk=False, last_n=20):
    if len(history_time) < 2:
        return None

    labels = [t.strftime('%H:%M') for t in list(history_time)][-last_n:]
    datasets = [
        {"label": "CPU %", "borderColor": "rgb(0,188,212)", "backgroundColor": "rgba(0,188,212,0.15)",
         "borderWidth": 2, "pointRadius": 1, "data": list(history_cpu)[-last_n:], "fill": True, "tension": 0.3},
        {"label": "RAM %", "borderColor": "rgb(233,30,99)", "backgroundColor": "rgba(233,30,99,0.15)",
         "borderWidth": 2, "pointRadius": 1, "data": list(history_ram)[-last_n:], "fill": True, "tension": 0.3}
    ]
    if include_disk:
        datasets.append({"label": "Disco %", "borderColor": "rgb(255,193,7)", "backgroundColor": "rgba(255,193,7,0.10)",
                         "borderWidth": 2, "pointRadius": 1, "data": list(history_disk)[-last_n:], "fill": True, "tension": 0.3})

    title_period = f"ultimos {last_n} min" if last_n <= 60 else f"ultimas {last_n // 60}h"
    chart_config = {
        "type": "line",
        "data": {"labels": labels, "datasets": datasets},
        "options": {
            "title": {"display": True, "text": f"Rendimiento — {SERVER_NAME} ({title_period})", "fontColor": "#fff", "fontSize": 14},
            "legend": {"labels": {"fontColor": "#ccc", "fontSize": 11}},
            "scales": {
                "xAxes": [{"ticks": {"fontColor": "#aaa", "fontSize": 9, "maxTicksLimit": 15}, "gridLines": {"color": "rgba(255,255,255,0.08)"}}],
                "yAxes": [{"ticks": {"fontColor": "#aaa", "beginAtZero": True, "max": 100, "fontSize": 10}, "gridLines": {"color": "rgba(255,255,255,0.08)"}}]
            }
        }
    }
    payload = {"backgroundColor": "#1a1a2e", "width": 700, "height": 320, "format": "png", "chart": chart_config}

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post("https://quickchart.io/chart", json=payload) as resp:
                if resp.status == 200:
                    return await resp.read()
                elif DEBUG_MODE:
                    print(f"Error Chart API: {resp.status}")
    except Exception as e:
        if DEBUG_MODE:
            print(f"Error Chart API: {e}")
    return None


async def get_guardian_fleet_image():
    """Captura el Fleet Overview completo y lo pagina para Discord."""
    if (
        grafana_client is None
        or not GRAFANA_GUARDIAN_ENABLED
        or not GRAFANA_GUARDIAN_DASHBOARD
    ):
        return None

    from_expr, to_expr = parse_range(
        GRAFANA_GUARDIAN_RANGE, GRAFANA_DEFAULT_RANGE
    )
    return await render_fleet_pages(
        grafana_client,
        GRAFANA_GUARDIAN_DASHBOARD,
        from_expr,
        to_expr,
        GRAFANA_GUARDIAN_W,
        GRAFANA_GUARDIAN_H,
        GRAFANA_GUARDIAN_PAGE_H,
        GRAFANA_THEME,
        GRAFANA_TZ,
    )


def _is_remote_alias(value):
    if not value or remote_arch_config is None:
        return False
    return value.strip().lower() in {
        remote_arch_config.key,
        remote_arch_config.name.lower(),
        "arch",
        "mbp",
        "server-mbp",
    }


def _remote_name():
    return remote_arch_config.name if remote_arch_config else "Arch"


def _format_uptime(seconds):
    seconds = max(0, int(seconds or 0))
    days, seconds = divmod(seconds, 86_400)
    hours, seconds = divmod(seconds, 3_600)
    minutes, _ = divmod(seconds, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return " ".join(parts)


def _remote_embed(title, *, color=0x3498db, description=None):
    embed = discord.Embed(
        title=title,
        description=description,
        color=color,
        timestamp=datetime.now(),
    )
    embed.set_footer(text=f"Nodo remoto: {_remote_name()} · agente SSH restringido")
    return embed


async def _remote_request(ctx, action, *args, status=None):
    if remote_arch is None:
        await ctx.send(
            "❌ El nodo Arch remoto no está configurado en este Centinela."
        )
        return None
    progress = await ctx.send(status) if status else None
    try:
        payload = await remote_arch.request(action, *args)
    except RemoteHostError as error:
        message = (
            f"❌ **{_remote_name()}** no respondió a `{action}`: "
            f"`{str(error)[:300]}`"
        )
        if progress:
            await progress.edit(content=message)
        else:
            await ctx.send(message)
        return None
    if progress:
        await progress.delete()
    return payload


def _remote_top_field(snapshot, key="cpu"):
    """Filas de procesos remotos, o el motivo por el que no las hay.

    Nunca devuelve una tabla vacia haciendola pasar por medicion: en el primer
    poll despues de un reinicio no existe muestra anterior contra la cual
    calcular el delta de CPU, y decirlo es mas util que publicar ceros.
    """
    processes = (snapshot or {}).get("processes") or {}
    rows = processes.get(key) or []
    if not rows:
        if not processes:
            return "_El agente remoto no reporta procesos (versión antigua)._"
        return "_Todavía sin muestra válida de procesos._"
    if key == "cpu" and not processes.get("warm"):
        return "_Primer muestreo tras reiniciar: sin ventana para medir CPU._"
    lines = []
    for row in rows[:4]:
        value = row.get(key)
        if value is None:
            continue
        name = str(row.get("container") or row.get("name") or "?")[:22]
        bar = "█" * min(int(value / 10), 10)
        lines.append(
            f"`{name:<22}` {value:>5.1f}% `{bar}`\n"
            f"　pid `{row.get('pid', '?')}`"
        )
    return "\n".join(lines) if lines else "_Sin procesos medibles._"


def _remote_alarm_embed(event, snapshot):
    alarm = event["alarm"]
    value = event["value"]
    state = event["to"]
    if state == OK:
        embed = _remote_embed(
            f"✅ Normalizado: {alarm.title}",
            description=(
                "Volvió a la normalidad tras "
                f"**{_fmt_dur(event['duration_s'])}** en alarma."
            ),
            color=0x2ecc71,
        )
    elif state == NO_DATA:
        embed = _remote_embed(
            f"❔ Sin datos: {alarm.title}",
            description=(
                f"{alarm.description}\n\nLa métrica dejó de poder medirse; "
                "no se interpreta como cero."
            ),
            color=0x95a5a6,
        )
    else:
        continuing = event["kind"] == "reminder"
        embed = _remote_embed(
            f"{alarm.title}{' (sigue)' if continuing else ''}",
            description=alarm.description,
            color=0xff0000 if alarm.severity == CRITICAL else 0xe67e22,
        )
        if value is not None:
            detail = (
                f"**{value:.1f}{alarm.unit}** "
                f"(umbral {alarm.threshold}{alarm.unit})"
            )
            if alarm.unit == "%":
                detail += f"\n{make_bar(value)}"
            embed.add_field(name="Valor", value=detail, inline=False)
        embed.add_field(
            name="Criterio",
            value=(
                f"{alarm.datapoints} de {alarm.periods} muestras en falta · "
                f"severidad **{alarm.severity}**"
            ),
            inline=False,
        )
        # El equivalente remoto de lo que build_alarm_embed ya hacia local:
        # una alarma de CPU al 98% sin decir quien la esta consumiendo obliga a
        # abrir una sesion para averiguar lo que el bot ya tenia en la mano.
        if alarm.name in ("cpu", "ram", "swap"):
            embed.add_field(
                name="Top procesos",
                value=_remote_top_field(
                    snapshot, "cpu" if alarm.name == "cpu" else "ram"
                ),
                inline=False,
            )
        if alarm.name == "temp" and snapshot.get("temperatures"):
            temps = snapshot["temperatures"]
            hottest = max(temps, key=temps.get)
            embed.add_field(
                name="Sensor más caliente",
                value=f"`{hottest}` — {temps[hottest]:.1f}°C",
                inline=False,
            )
        if alarm.name == "swap":
            embed.add_field(
                name="Swap usado",
                value=format_bytes(snapshot.get("swap_used", 0)),
                inline=True,
            )
        if alarm.action:
            embed.add_field(
                name="💡 Sugerencia", value=alarm.action, inline=False
            )
    if value is not None and state in (OK, NO_DATA):
        embed.add_field(
            name="Valor actual",
            value=f"{value:.1f}{alarm.unit}",
            inline=True,
        )
    return embed


async def _remote_status_command(ctx):
    snapshot = await _remote_request(
        ctx, "snapshot", status=f"📊 Consultando **{_remote_name()}**..."
    )
    if not snapshot:
        return
    score = 100
    cpu = float(snapshot.get("cpu_percent", 0))
    ram = float(snapshot.get("ram_percent", 0))
    disk = float(snapshot.get("disk_percent", 0))
    if cpu > 50:
        score -= cpu - 50
    if ram > 80:
        score -= ram - 80
    if not snapshot.get("network_up", True):
        score -= 25
    score = max(0, int(score))
    embed = _remote_embed(
        f"🎛 Panel de Control — {_remote_name()}",
        color=health_color(score),
    )
    embed.add_field(
        name="🏆 Health",
        value=f"{health_emoji(score)} **{score}/100**",
        inline=True,
    )
    embed.add_field(
        name="⏱ Uptime",
        value=f"`{_format_uptime(snapshot.get('uptime_seconds'))}`",
        inline=True,
    )
    embed.add_field(name="\u200b", value="\u200b", inline=True)
    embed.add_field(name="🖥 CPU", value=make_bar(cpu), inline=False)
    embed.add_field(
        name="🧠 RAM",
        value=(
            f"{make_bar(ram)}\n"
            f"`{format_bytes(snapshot.get('ram_used', 0))} / "
            f"{format_bytes(snapshot.get('ram_total', 0))}`"
        ),
        inline=False,
    )
    embed.add_field(
        name="💾 Disco",
        value=(
            f"{make_bar(disk)}\n"
            f"`{format_bytes(snapshot.get('disk_used', 0))} / "
            f"{format_bytes(snapshot.get('disk_total', 0))}`"
        ),
        inline=False,
    )
    if snapshot.get("swap_total", 0):
        embed.add_field(
            name="🔄 Swap",
            value=make_bar(snapshot.get("swap_percent", 0)),
            inline=False,
        )
    embed.add_field(
        name="🌐 Red",
        value=(
            f"{'🟢' if snapshot.get('network_up') else '🔴'} Internet · "
            f"↑ `{format_bytes(snapshot.get('net_sent', 0))}` "
            f"↓ `{format_bytes(snapshot.get('net_recv', 0))}`"
        ),
        inline=False,
    )
    temps = snapshot.get("temperatures") or {}
    if temps:
        hottest = max(temps, key=temps.get)
        value = temps[hottest]
        icon = "🔴" if value > REMOTE_ARCH_TEMP_ALERT_C else (
            "🟡" if value > 70 else "🟢"
        )
        embed.add_field(
            name="🌡 Temp",
            value=f"{icon} `{hottest}`: **{value:.1f}°C**",
            inline=False,
        )
    await ctx.send(embed=embed)


async def _remote_top_command(ctx):
    payload = await _remote_request(ctx, "top", 8)
    if not payload:
        return
    embed = _remote_embed(f"📊 Top Procesos — {_remote_name()}")
    for key, title in (("cpu", "🖥 Por CPU"), ("ram", "🧠 Por RAM")):
        rows = payload.get(key) or []
        lines = [
            f"`{row['pid']:>6}` `{row[key]:>5.1f}%` {row['name'][:32]}"
            for row in rows
        ]
        embed.add_field(
            name=title, value="\n".join(lines) or "Sin datos", inline=False
        )
    await ctx.send(embed=embed)


async def _remote_sessions_command(ctx):
    payload = await _remote_request(ctx, "sessions")
    if not payload:
        return
    sessions_now = payload.get("sessions") or []
    embed = _remote_embed(f"👥 Sesiones Activas — {_remote_name()}")
    if not sessions_now:
        embed.description = "No hay sesiones activas."
    for session in sessions_now[:12]:
        host = session.get("host") or "local"
        is_local = host == "local" or any(
            host.startswith(subnet) for subnet in SAFE_SUBNETS
        )
        embed.add_field(
            name=f"{'🟢' if is_local else '🟡'} {session.get('user', '?')}",
            value=(
                f"IP: `{host}`\nTTY: `{session.get('terminal', '?')}`\n"
                f"Desde: `{session.get('started', '?')}`"
            ),
            inline=True,
        )
    await ctx.send(embed=embed)


async def _remote_temps_command(ctx):
    snapshot = await _remote_request(ctx, "snapshot")
    if not snapshot:
        return
    temps = snapshot.get("temperatures") or {}
    embed = _remote_embed(f"🌡 Temperaturas — {_remote_name()}")
    if not temps:
        embed.description = (
            "No se pudieron leer sensores. El nodo sigue figurando, pero la "
            "temperatura queda explícitamente sin datos."
        )
        embed.color = 0xe67e22
    for label, temp in sorted(
        temps.items(), key=lambda item: item[1], reverse=True
    ):
        icon = "🔴" if temp > REMOTE_ARCH_TEMP_ALERT_C else (
            "🟡" if temp > 70 else "🟢"
        )
        length = min(12, int(temp / 100 * 12))
        embed.add_field(
            name=f"{icon} {label}",
            value=f"`{'█' * length}{'░' * (12 - length)}` **{temp:.1f}°C**",
            inline=False,
        )
    await ctx.send(embed=embed)


async def _remote_ports_command(ctx):
    payload = await _remote_request(ctx, "ports")
    if not payload:
        return
    ports = payload.get("ports") or []
    embed = _remote_embed(f"🔌 Puertos Abiertos — {_remote_name()}")
    if not ports:
        embed.description = "No se detectaron puertos en escucha."
    else:
        embed.description = "\n".join(
            f"{'🌐' if row['ip'] in ('0.0.0.0', '::') else '🏠'} "
            f"`{row['ip']}:{row['port']}` → `{row['process']}`"
            for row in ports[:30]
        )
    await ctx.send(embed=embed)


async def _remote_smart_command(ctx):
    payload = await _remote_request(
        ctx, "smart", status=f"🔍 Leyendo SMART en **{_remote_name()}**..."
    )
    if not payload:
        return
    if not payload.get("available"):
        return await ctx.send(
            f"❌ `smartctl` no está instalado en **{_remote_name()}**."
        )
    output = payload.get("output") or ""
    healthy = payload.get("healthy", False)
    embed = _remote_embed(
        f"💿 Disco — {payload.get('device') or _remote_name()}",
        color=0x2ecc71 if healthy else 0xe67e22,
    )
    embed.add_field(
        name="Estado",
        value="✅ PASSED" if healthy else "⚠️ Sin confirmación de salud",
        inline=True,
    )
    keywords = (
        "Percentage Used", "Available Spare", "Temperature",
        "Power On Hours", "Data Units", "Reallocated_Sector",
        "Wear_Leveling", "Media_Wearout",
    )
    lines = [
        f"`{line.strip()[:80]}`"
        for line in output.splitlines()
        if any(key in line for key in keywords)
    ]
    if lines:
        embed.add_field(name="Atributos", value="\n".join(lines[:10]), inline=False)
    await ctx.send(embed=embed)


async def _remote_services_command(ctx):
    snapshot = await _remote_request(ctx, "snapshot")
    if not snapshot:
        return
    services_now = snapshot.get("services") or {}
    embed = _remote_embed(f"⚙️ Servicios — {_remote_name()}")
    if not services_now:
        embed.description = "No hay servicios configurados para vigilar."
    for name, status in services_now.items():
        icon = {"active": "🟢", "inactive": "🔴", "failed": "💀"}.get(
            status, "🟡"
        )
        embed.add_field(
            name=f"{icon} {name}", value=f"`{status}`", inline=True
        )
    embed.color = (
        0x2ecc71
        if services_now and all(v == "active" for v in services_now.values())
        else 0xe74c3c
    )
    await ctx.send(embed=embed)


async def _remote_containers_command(ctx):
    payload = await _remote_request(ctx, "docker")
    if not payload:
        return
    if not payload.get("available"):
        return await ctx.send(f"🐳 Docker no está instalado en **{_remote_name()}**.")
    containers = payload.get("containers") or []
    if not containers:
        return await ctx.send(f"🐳 **{_remote_name()}** no tiene contenedores.")
    down = sum(
        1 for item in containers if item.get("state", "").lower() != "running"
    )
    embed = _remote_embed(
        f"🐳 Contenedores — {_remote_name()}",
        color=0xe74c3c if down else 0x2ecc71,
    )
    for item in containers[:18]:
        state = item.get("state", "").lower()
        icon = {"running": "🟢", "restarting": "🔄", "exited": "🔴"}.get(
            state, "🟡"
        )
        value = (
            f"`{item.get('status') or state or '?'}`\n"
            f"`{item.get('image') or '?'}`"
        )
        if item.get("ports"):
            value += f"\n`{item['ports'][:70]}`"
        value += (
            f"\nCPU: `{item.get('cpu', 0):.1f}%` "
            f"RAM: `{item.get('ram', 0):.1f}%`"
        )
        embed.add_field(
            name=f"{icon} {item.get('name') or '?'}",
            value=value,
            inline=True,
        )
    await ctx.send(embed=embed)


async def _remote_logs_command(ctx, service):
    payload = await _remote_request(ctx, "logs", service, 25)
    if not payload:
        return
    embed = _remote_embed(f"📋 Logs: {service}")
    embed.description = f"```\n{(payload.get('output') or 'Sin salida.')[-1800:]}\n```"
    await ctx.send(embed=embed)


async def _remote_restart_command(ctx, service):
    payload = await _remote_request(
        ctx, "restart", service,
        status=f"🔄 Reiniciando `{service}` en **{_remote_name()}**...",
    )
    if not payload:
        return
    await ctx.send(embed=_remote_embed(
        f"✅ Reiniciado: {service}",
        description=f"Por **{ctx.author.display_name}**.",
        color=0x2ecc71,
    ))


async def _remote_updates_command(ctx):
    payload = await _remote_request(
        ctx, "updates",
        status=f"🔄 Consultando actualizaciones en **{_remote_name()}**...",
    )
    if not payload:
        return
    updates = payload.get("updates") or []
    if not updates:
        embed = _remote_embed(
            f"✅ Sistema Actualizado — {_remote_name()}", color=0x2ecc71
        )
    else:
        embed = _remote_embed(
            f"📦 {len(updates)} Actualizaciones — {_remote_name()}",
            color=0xe67e22,
        )
        lines = [
            f"- **{item['package']}**\n  `{item['old']}` → `{item['new']}`"
            for item in updates[:12]
        ]
        if len(updates) > 12:
            lines.append(f"\n_...y {len(updates) - 12} más._")
        embed.description = "\n".join(lines)
        embed.set_footer(
            text=f"Nodo remoto: {_remote_name()} · aplicar con sudo pacman -Syu"
        )
    await ctx.send(embed=embed)


async def _remote_backups_command(ctx):
    payload = await _remote_request(ctx, "backup")
    if not payload:
        return
    if not payload.get("configured"):
        return await ctx.send(
            f"❌ Backup no configurado en **{_remote_name()}**."
        )
    if not payload.get("exists"):
        return await ctx.send(
            f"❌ El repositorio de backup de **{_remote_name()}** no existe."
        )
    timestamp = payload.get("last_timestamp")
    if not timestamp:
        return await ctx.send(
            f"❌ No se encontró `index.*` en el backup de **{_remote_name()}**."
        )
    modified = datetime.fromtimestamp(timestamp)
    age = datetime.now() - modified
    healthy = age < timedelta(hours=25)
    embed = _remote_embed(
        f"💾 Backup Borg — {_remote_name()}",
        color=0x2ecc71 if healthy else 0xff0000,
    )
    embed.add_field(
        name="Índice", value=f"`{payload.get('index', '?')}`", inline=False
    )
    embed.add_field(
        name="Última ejecución",
        value=modified.strftime("%d/%m/%Y %H:%M"),
        inline=True,
    )
    embed.add_field(
        name="Antigüedad", value=str(age).split(".")[0], inline=True
    )
    embed.add_field(
        name="Tamaño repo",
        value=format_bytes(payload.get("size", 0)),
        inline=True,
    )
    embed.add_field(
        name="Estado",
        value="✅ Al día" if healthy else "🔴 Desactualizado",
        inline=False,
    )
    await ctx.send(embed=embed)


# ==========================================
# EVENTOS Y TAREAS
# ==========================================
@bot.event
async def on_ready():
    print(f"Bot Centinela ONLINE: {bot.user}")
    for task in [collect_history, watch_resources, watch_docker_loops, watch_docker_resources, guardian_report, watch_network, watch_speed]:
        if not task.is_running():
            task.start()
    if BACKUP_PATH and not watch_backups.is_running():
        watch_backups.start()
    if WATCHED_SERVICES and not watch_services.is_running():
        watch_services.start()
    if FAIL2BAN_ENABLED and not watch_fail2ban.is_running():
        watch_fail2ban.start()
    if cloudflare_client is not None and not watch_cloudflare_access.is_running():
        watch_cloudflare_access.start()
    if not refresh_key_directories.is_running():
        # Antes del primer login posible: sin el directorio cargado, toda clave
        # se veria como no reconocida y el primer aviso seria un falso positivo.
        await refresh_key_directories()
        refresh_key_directories.start()
    if remote_arch is not None:
        for task in [
            watch_remote_arch,
            watch_remote_security,
            watch_remote_docker,
            watch_remote_backups,
        ]:
            if not task.is_running():
                task.start()

    # FIX: evitar lanzar multiples instancias del watcher en reconexiones
    if not getattr(bot, '_ssh_watcher_started', False):
        bot._ssh_watcher_started = True
        bot.loop.create_task(watch_ssh_logs())

    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        cmds = (
            "**Monitoreo**\n"
            "`!status`    Panel de control\n"
            "`!top`       Procesos top CPU/RAM\n"
            "`!temps`     Temperaturas\n"
            "`!ports`     Puertos abiertos\n"
            "`!smart`     Salud del disco\n"
            "`!who`       Sesiones activas\n\n"
            "**Servicios**\n"
            "`!ct`        Contenedores (estado en vivo)\n"
            "`!services`  Servicios systemd\n"
            "`!logs <s>`  Logs de un servicio\n"
            "`!restart <s>` Reiniciar un servicio\n\n"
            "**Mantenimiento**\n"
            "`!updates`   Actualizaciones\n"
            "`!backups`   Estado de backups\n\n"
            "**Nodo Arch unificado**\n"
            "`!arch`      Panel remoto\n"
            "`!arch help` Comandos del nodo remoto\n"
            "_También podés agregar `arch`: `!status arch`, "
            "`!logs <s> arch`._\n\n"
            "**Red y alarmas**\n"
            "`!red`       Diagnóstico por capas\n"
            "`!speedtest` Medición contra baseline\n"
            "`!alarmas`   Estado de las alarmas\n\n"
            "_Imagenes Docker y CVEs los maneja el Updates-Bot:_\n"
            "_`!docker status` · `!cve host` — de toda la flota._"
        )
        if grafana_client is not None:
            cmds += (
                "\n\n**Grafana**\n"
                "`!grafana`          Lista dashboards\n"
                "`!grafana <d>`      Lista paneles\n"
                "`!grafana <d> <p>`  Render de un panel\n"
                "`!grafana <d> full` Dashboard completo"
            )
        embed = discord.Embed(
            title=f"Centinela v7.0 ONLINE — {SERVER_NAME}",
            description=f"Monitoreo activo. Distro: **{DISTRO}**.",
            color=0x2ecc71
        )
        embed.add_field(name="Comandos disponibles", value=cmds, inline=False)
        svc_str = ", ".join(WATCHED_SERVICES) if WATCHED_SERVICES else "Ninguno"
        embed.add_field(name="Servicios vigilados", value=f"`{svc_str}`", inline=False)
        embed.set_footer(text=f"Iniciado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        await channel.send(embed=embed)


@tasks.loop(minutes=1)
async def watch_remote_arch():
    """Collect and correlate the remote node without granting a remote shell."""
    global remote_last_snapshot, remote_consecutive_failures, remote_down_since
    global remote_network_down_since
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or remote_arch is None:
        return
    try:
        snapshot = await remote_arch.request("snapshot")
    except RemoteHostError as error:
        remote_consecutive_failures += 1
        if remote_consecutive_failures == 2:
            remote_down_since = datetime.now()
            remote_stats_counter["agent_failures"] += 1
            await channel.send(embed=_remote_embed(
                f"🔴 Nodo sin respuesta — {_remote_name()}",
                description=(
                    "Fallaron dos consultas consecutivas al agente restringido.\n"
                    f"`{str(error)[:500]}`"
                ),
                color=0xe74c3c,
            ))
        return

    now = datetime.now()
    if remote_consecutive_failures >= 2:
        duration = (
            now - remote_down_since if remote_down_since else timedelta()
        )
        await channel.send(embed=_remote_embed(
            f"🟢 Nodo recuperado — {_remote_name()}",
            description=f"Volvió a responder tras **{str(duration).split('.')[0]}**.",
            color=0x2ecc71,
        ))
    remote_consecutive_failures = 0
    remote_down_since = None
    remote_last_snapshot = snapshot
    remote_history_time.append(now)
    remote_history_cpu.append(float(snapshot.get("cpu_percent", 0)))
    remote_history_ram.append(float(snapshot.get("ram_percent", 0)))
    remote_history_disk.append(float(snapshot.get("disk_percent", 0)))
    remote_history_swap.append(float(snapshot.get("swap_percent", 0)))

    temperatures_now = snapshot.get("temperatures") or {}
    metrics = {
        "cpu": snapshot.get("cpu_percent"),
        "ram": snapshot.get("ram_percent"),
        "disco": snapshot.get("disk_percent"),
        "swap": snapshot.get("swap_percent"),
        "temp": max(temperatures_now.values()) if temperatures_now else None,
    }
    for event in remote_alarm_engine.evaluate(metrics):
        await channel.send(embed=_remote_alarm_embed(event, snapshot))

    for service, status in (snapshot.get("services") or {}).items():
        previous = remote_last_service_status.get(service)
        if previous == "active" and status != "active":
            remote_stats_counter["service_alerts"] += 1
            await channel.send(embed=_remote_embed(
                f"🔴 Servicio caído — {_remote_name()}",
                description=f"`{service}` pasó a **{status}**.",
                color=0xe74c3c,
            ))
        elif previous is not None and previous != "active" and status == "active":
            await channel.send(embed=_remote_embed(
                f"🟢 Servicio recuperado — {_remote_name()}",
                description=f"`{service}` volvió a **active**.",
                color=0x2ecc71,
            ))
        remote_last_service_status[service] = status

    if not snapshot.get("network_up", False):
        if remote_network_down_since is None:
            remote_network_down_since = now
            await channel.send(embed=_remote_embed(
                f"🌐 Red caída — {_remote_name()}",
                description="El nodo responde por LAN, pero no alcanza Internet.",
                color=0xe74c3c,
            ))
    elif remote_network_down_since is not None:
        duration = now - remote_network_down_since
        await channel.send(embed=_remote_embed(
            f"🌐 Red restaurada — {_remote_name()}",
            description=f"Internet volvió tras **{str(duration).split('.')[0]}**.",
            color=0x2ecc71,
        ))
        remote_network_down_since = None


def _remember_remote_security(key):
    if key in remote_security_seen:
        return False
    if len(remote_security_seen_order) == remote_security_seen_order.maxlen:
        remote_security_seen.discard(remote_security_seen_order.popleft())
    remote_security_seen.add(key)
    remote_security_seen_order.append(key)
    return True


async def _notify_remote_ssh_login(channel, event, timestamp):
    remote_stats_counter["ssh_events"] += 1
    origin_ip = event["ip"]
    cloudflare_event = None
    correlation_status = "direct"
    if is_loopback(origin_ip):
        cloudflare_event, correlation_status = await _correlate_cloudflare_login(
            channel, timestamp
        )
    real_ip = cloudflare_event.ip if cloudflare_event else origin_ip
    country = (
        _country_from_event(cloudflare_event)
        if cloudflare_event else country_resolver.resolve(real_ip)
    )
    remote_security_events.add(
        "ssh_login",
        ip=real_ip,
        user=event.get("user", ""),
        timestamp=timestamp,
        transport_ip=origin_ip,
        cloudflare_ray=(
            cloudflare_event.metadata.get("ray_id")
            if cloudflare_event else ""
        ),
        cloudflare_correlation=correlation_status,
        country=country.label if country else "",
        country_source=country.source if country else "",
    )
    origin = classify_ssh_origin(
        origin_ip,
        real_ip,
        SAFE_SUBNETS,
        correlated=cloudflare_event is not None,
    )
    identity, recognized = _key_identity_field(remote_key_directory, event)
    verdict = _assess_login(
        _remote_name(), event, remote_key_directory, timestamp
    )
    suspicious = bool(verdict and verdict.suspicious)
    embed = _remote_embed(
        (
            f"🚨 Login SSH sospechoso — {_remote_name()}"
            if suspicious
            else f"🔑 Nuevo Login SSH — {_remote_name()}"
        ),
        color=(
            0xff0000
            if suspicious
            else (
                0xf1c40f
                if origin["unresolved_proxy"] or not recognized
                else (0x2ecc71 if origin["is_local"] else 0xe67e22)
            )
        ),
    )
    embed.add_field(
        name="👤 Usuario", value=f"`{event.get('user', '?')}`", inline=True
    )
    embed.add_field(
        name="🌐 IP pública (Cloudflare)" if cloudflare_event else "🌐 IP observada",
        value=f"`{real_ip}`",
        inline=True,
    )
    embed.add_field(
        name="🏠 Origen",
        value=origin["label"],
        inline=True,
    )
    embed.add_field(name="🔐 Clave", value=identity, inline=False)
    anomalies = _anomaly_field(verdict)
    if anomalies:
        embed.add_field(
            name="🚩 Anomalías" if suspicious else "ℹ️ Notas",
            value=anomalies,
            inline=False,
        )
    if cloudflare_event:
        embed.add_field(
            name="☁️ Cloudflare Access",
            value=(
                f"`{cloudflare_event.user or 'usuario desconocido'}` · "
                f"Ray `{cloudflare_event.metadata.get('ray_id') or '?'}`\n"
                "Correlación temporal; sshd vio "
                f"`{origin_ip}`."
            ),
            inline=False,
        )
    elif origin["unresolved_proxy"]:
        embed.add_field(
            name="☁️ Cloudflare Access",
            value=_cloudflare_correlation_note(
                correlation_status, origin_ip
            ),
            inline=False,
        )
    _add_country_field(embed, country)
    await channel.send(embed=embed)


async def _notify_remote_ssh_fail(channel, event, timestamp):
    remote_stats_counter["ssh_fails"] += 1
    ip = event.get("ip") or "desconocida"
    remote_security_events.add(
        "ssh_fail",
        ip=ip,
        user=event.get("user", ""),
        timestamp=timestamp,
    )
    summary = remote_security_events.summarize_ip(
        ip,
        now=timestamp,
        max_age_seconds=REMOTE_ARCH_SSH_FAIL_WINDOW,
    )
    key = f"bruteforce:{ip}"
    now = datetime.now()
    if (
        SSH_FAIL_NOTIFY_ENABLED
        and summary["ssh_fails"] < REMOTE_ARCH_SSH_FAIL_THRESHOLD
        and _should_notify_fail(
            ssh_fail_notified, f"{_remote_name()}:{ip}", now
        )
    ):
        await channel.send(embed=_build_ssh_fail_embed(
            event, summary, node=_remote_name()
        ))
    if (
        summary["ssh_fails"] >= REMOTE_ARCH_SSH_FAIL_THRESHOLD
        and now - remote_last_alert_time.get(key, datetime.min) > ALERT_COOLDOWN
    ):
        embed = _remote_embed(
            f"🚨 Posible Brute Force SSH — {_remote_name()}",
            description=(
                f"**{summary['ssh_fails']} intentos fallidos correlacionados** "
                "desde la misma IP."
            ),
            color=0xff0000,
        )
        embed.add_field(name="🌐 IP", value=f"`{ip}`", inline=True)
        _add_country_field(embed, country_resolver.resolve(ip))
        if summary["users"]:
            embed.add_field(
                name="👥 Usuarios probados",
                value=", ".join(
                    f"`{user}`" for user in summary["users"][:10]
                ),
                inline=True,
            )
        await channel.send(embed=embed)
        remote_last_alert_time[key] = now


async def _notify_remote_fail2ban(channel, event, timestamp):
    ip = event["ip"]
    jail = event["jail"]
    if event["action"] == "unban":
        remote_security_events.add(
            "fail2ban_unban", ip=ip, timestamp=timestamp, jail=jail
        )
        return
    remote_stats_counter["fail2ban_bans"] += 1
    summary = remote_security_events.summarize_ip(ip, now=timestamp)
    remote_security_events.add(
        "fail2ban_ban", ip=ip, timestamp=timestamp, jail=jail
    )
    embed = _remote_embed(
        f"⛔ Fail2ban bloqueó una IP — {_remote_name()}",
        description=f"`{ip}` fue baneada por la jail `{jail}`.",
        color=0xe74c3c,
    )
    _add_country_field(embed, country_resolver.resolve(ip))
    embed.add_field(
        name="🔗 Correlación",
        value=(
            f"{summary['ssh_fails']} fallo(s) SSH recientes"
            if summary["ssh_fails"]
            else "Sin fallos SSH correlacionables en la ventana reciente"
        ),
        inline=True,
    )
    if summary["users"]:
        embed.add_field(
            name="👥 Usuarios probados",
            value=", ".join(f"`{user}`" for user in summary["users"][:10]),
            inline=True,
        )
    await channel.send(embed=embed)


@tasks.loop(minutes=1)
async def watch_remote_security():
    global remote_security_since
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or remote_arch is None:
        return
    requested_since = remote_security_since - timedelta(seconds=5)
    try:
        payload = await remote_arch.request(
            "security", int(requested_since.timestamp())
        )
    except RemoteHostError as error:
        if DEBUG_MODE:
            print(f"Remote security watcher: {error}", file=sys.stderr)
        return
    newest = remote_security_since
    for item in payload.get("events") or []:
        timestamp = parse_timestamp(
            datetime.fromtimestamp(
                float(item.get("timestamp", 0)), tz=utcnow().tzinfo
            )
        )
        newest = max(newest, timestamp)
        message = str(item.get("message") or "")
        key = (
            f"{item.get('timestamp', 0)}|{item.get('unit', '')}|{message}"
        )
        if not _remember_remote_security(key):
            continue
        ssh_event = parse_ssh_line(message)
        if ssh_event:
            if ssh_event["kind"] == "ssh_login":
                await _notify_remote_ssh_login(channel, ssh_event, timestamp)
            else:
                await _notify_remote_ssh_fail(channel, ssh_event, timestamp)
            continue
        fail2ban_event = parse_fail2ban_log(message)
        if fail2ban_event:
            await _notify_remote_fail2ban(
                channel, fail2ban_event, timestamp
            )
    remote_security_since = newest


@tasks.loop(minutes=5)
async def watch_remote_docker():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or remote_arch is None:
        return
    try:
        payload = await remote_arch.request("docker")
    except RemoteHostError as error:
        if DEBUG_MODE:
            print(f"Remote Docker watcher: {error}", file=sys.stderr)
        return
    now = datetime.now()
    for container in payload.get("containers") or []:
        name = container.get("name") or ""
        if not name:
            continue
        state = (container.get("state") or "").lower()
        if state == "restarting":
            previous_heal = remote_docker_heal_attempts.get(name, datetime.min)
            if now - previous_heal > HEAL_TIMEOUT:
                remote_docker_heal_attempts[name] = now
                try:
                    await remote_arch.request("heal", name, timeout=70)
                    remote_stats_counter["docker_alerts"] += 1
                    await channel.send(embed=_remote_embed(
                        f"🩹 Auto-Healing — {_remote_name()}",
                        description=f"`{name}` estaba reiniciando y fue reiniciado.",
                        color=0x3498db,
                    ))
                except RemoteHostError as error:
                    await channel.send(embed=_remote_embed(
                        f"🔄 Docker Loop — {_remote_name()}",
                        description=(
                            f"`{name}` sigue reiniciando y el intento de "
                            f"recuperación falló.\n`{str(error)[:500]}`"
                        ),
                        color=0xe67e22,
                    ))
                continue
        cpu = float(container.get("cpu", 0))
        ram = float(container.get("ram", 0))
        alert_key = f"resource:{name}"
        if (
            (cpu > 90 or ram > 90)
            and now - remote_last_docker_alert.get(
                alert_key, datetime.min
            ) > ALERT_COOLDOWN
        ):
            embed = _remote_embed(
                f"🐳 Alto Consumo — {name} — {_remote_name()}",
                color=0xe67e22,
            )
            if cpu > 90:
                embed.add_field(name="CPU", value=f"**{cpu:.1f}%**", inline=True)
            if ram > 90:
                embed.add_field(
                    name="RAM",
                    value=f"**{ram:.1f}%** ({container.get('mem_usage', '')})",
                    inline=True,
                )
            await channel.send(embed=embed)
            remote_last_docker_alert[alert_key] = now
            remote_stats_counter["docker_alerts"] += 1


@tasks.loop(hours=24)
async def watch_remote_backups():
    global remote_backup_alerted
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or remote_arch is None:
        return
    try:
        payload = await remote_arch.request("backup")
    except RemoteHostError as error:
        if DEBUG_MODE:
            print(f"Remote backup watcher: {error}", file=sys.stderr)
        return
    timestamp = payload.get("last_timestamp")
    stale = (
        payload.get("configured")
        and payload.get("exists")
        and (
            not timestamp
            or datetime.now() - datetime.fromtimestamp(timestamp)
            > timedelta(hours=25)
        )
    )
    if stale and not remote_backup_alerted:
        remote_backup_alerted = True
        await channel.send(embed=_remote_embed(
            f"🚨 Backup desactualizado — {_remote_name()}",
            description=(
                "El repositorio no tiene un índice reciente."
                if not timestamp else
                "Último índice: "
                f"`{datetime.fromtimestamp(timestamp):%d/%m/%Y %H:%M}`."
            ),
            color=0xff0000,
        ))
    elif not stale:
        remote_backup_alerted = False


@tasks.loop(minutes=1)
async def collect_history():
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    swap = psutil.swap_memory().percent

    # Refresca las tasas por proceso desde el loop que ya corre cada minuto, en
    # un thread para no frenar el event loop barriendo /proc. Asi las alertas
    # leen datos calientes sin dormir: la lectura es el promedio del ultimo
    # minuto, que es justo la ventana de una alerta sostenida.
    await asyncio.to_thread(procmon.sampler.refresh)

    history_time.append(datetime.now())
    history_cpu.append(cpu)
    history_ram.append(ram)
    history_disk.append(disk)
    history_swap.append(swap)

@tasks.loop(minutes=2)
async def watch_resources():
    """Evalua las metricas del host contra el motor de alarmas.

    Antes esto eran cinco bloques `if valor > umbral and cooldown` escritos a
    mano, cada uno con su propia nocion de cuando avisar y ninguno con aviso de
    recuperacion. Ahora solo se miden las metricas y el motor decide.
    """
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return

    temps = get_temperatures()
    swap = psutil.swap_memory()
    metricas = {
        "cpu": history_cpu[-1] if history_cpu else None,
        "ram": history_ram[-1] if history_ram else None,
        "disco": psutil.disk_usage('/').percent,
        "swap": swap.percent,
        # None y no 0: un sensor que desaparece no es un equipo frio, y el
        # motor lo distingue pasando la alarma a INSUFFICIENT_DATA.
        "temp": max(temps.values()) if temps else None,
    }

    for evento in alarm_engine.evaluate(metricas):
        await channel.send(embed=build_alarm_embed(evento, temps=temps, swap=swap))
        stats_counter["alerts"] = stats_counter.get("alerts", 0) + 1

@tasks.loop(minutes=5)
async def watch_services():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or not WATCHED_SERVICES:
        return
    for svc in WATCHED_SERVICES:
        status = await asyncio.to_thread(get_service_status, svc)
        prev = last_service_status.get(svc)
        if prev is not None and prev == "active" and status != "active":
            embed = discord.Embed(title=f"🔴 Servicio Caido: {svc}", description=f"`{svc}` paso a **{status}**.", color=0xff0000)
            log = await asyncio.to_thread(get_service_logs, svc, 5)
            if log:
                embed.add_field(name="Log", value=f"```\n{log[:500]}\n```", inline=False)
            await channel.send(embed=embed)
            stats_counter["service_alerts"] += 1
        elif prev is not None and prev != "active" and status == "active":
            embed = discord.Embed(title=f"🟢 Servicio Recuperado: {svc}", color=0x2ecc71)
            await channel.send(embed=embed)
        last_service_status[svc] = status

async def _command_output(args, timeout=15):
    """Run a fixed argv command without a shell and return (ok, stdout)."""
    try:
        result = await asyncio.to_thread(
            subprocess.run,
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return result.returncode == 0, result.stdout
    except (OSError, subprocess.SubprocessError):
        return False, ""


@tasks.loop(minutes=1)
async def watch_fail2ban():
    """Notify bans using the client when permitted, journald as fallback."""
    global fail2ban_journal_since
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return
    ok, output = await _command_output(["fail2ban-client", "status"])
    if not ok:
        # The control socket is often root-only. The bot already needs journal
        # read access for sshd, so journald is a safe, read-only fallback.
        since = fail2ban_journal_since
        fail2ban_journal_since = utcnow() - timedelta(seconds=5)
        ok, output = await _command_output([
            "journalctl", "-u", "fail2ban",
            "--since", f"@{since.timestamp():.0f}",
            "--no-pager", "-o", "cat",
        ])
        if not ok:
            return
        for line in output.splitlines():
            event = parse_fail2ban_log(line)
            if not event:
                continue
            key = (event["jail"], event["ip"])
            if event["action"] == "unban":
                active_ban_notifications.discard(key)
            elif key not in active_ban_notifications:
                active_ban_notifications.add(key)
                await _notify_fail2ban_ban(
                    channel, event["jail"], event["ip"]
                )
        return

    for jail in parse_fail2ban_jails(output):
        ok, jail_output = await _command_output(
            ["fail2ban-client", "status", jail]
        )
        if not ok:
            continue
        current = parse_fail2ban_banned(jail_output)
        previous = fail2ban_banned.get(jail)
        fail2ban_banned[jail] = current
        if previous is None:
            active_ban_notifications.update((jail, ip) for ip in current)
            continue  # establish baseline without replaying old bans on restart
        for ip in previous - current:
            active_ban_notifications.discard((jail, ip))
        for ip in sorted(current - previous):
            key = (jail, ip)
            if key not in active_ban_notifications:
                active_ban_notifications.add(key)
                await _notify_fail2ban_ban(channel, jail, ip)


async def _notify_fail2ban_ban(channel, jail, ip):
    stats_counter["fail2ban_bans"] += 1
    summary = security_events.summarize_ip(ip)
    security_events.add("fail2ban_ban", ip=ip, jail=jail)
    embed = discord.Embed(
        title="⛔ Fail2ban bloqueó una IP",
        description=f"`{ip}` fue baneada por la jail `{jail}`.",
        color=0xe74c3c,
        timestamp=datetime.now(),
    )
    _add_country_field(embed, country_resolver.resolve(ip))
    embed.add_field(
        name="🔗 Correlación",
        value=(
            f"{summary['ssh_fails']} fallo(s) SSH recientes"
            if summary["ssh_fails"] else
            "Sin fallos SSH correlacionables en la ventana reciente"
        ),
        inline=True,
    )
    if summary["users"]:
        embed.add_field(
            name="👥 Usuarios probados",
            value=", ".join(f"`{user}`" for user in summary["users"][:10]),
            inline=True,
        )
    await channel.send(embed=embed)


@tasks.loop(minutes=1)
async def watch_cloudflare_access():
    """Poll Access logs: the client public IP is unavailable at an SSH origin."""
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or cloudflare_client is None:
        return
    await _refresh_cloudflare_access(channel, cloudflare_since)


def _probe_lines(probes):
    """Las capas como se muestran en Discord, en orden de escalera."""
    icon = {netdiag.OK: "🟢", netdiag.FAIL: "🔴", netdiag.SKIP: "⚪"}
    order = {name: i for i, name in enumerate(netdiag.LAYER_ORDER)}
    rows = sorted(probes, key=lambda p: order.get(p.layer, 99))
    return "\n".join(
        f"{icon.get(p.state, '⚪')} `{p.layer:<7}` {p.detail}"
        + (f" _({p.ms:.0f}ms)_" if p.ms else "")
        for p in rows
    )


@tasks.loop(minutes=3)
async def watch_network():
    """Vigila la red y reporta QUE capa fallo, no solo que 'se fue internet'.

    El loop viejo tenia un agujero: al detectar el corte solo seteaba un flag y
    no mandaba nada, asi que el unico aviso llegaba cuando la red YA habia
    vuelto. Ahora avisa en el momento, con la capa culpable.
    """
    global network_down_layer, network_down_since
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return

    probes, guardian = await asyncio.to_thread(netdiag.run_all_probes)
    verdict = netdiag.diagnose(probes)
    now = datetime.now()

    if not verdict["healthy"]:
        layer = verdict["layer"]
        # Se avisa al caer y tambien si la falla se MUEVE a otra capa: es un
        # cambio de diagnostico, no repeticion del mismo aviso.
        if layer != network_down_layer:
            network_down_layer = layer
            network_down_since = network_down_since or now
            embed = discord.Embed(
                title=verdict["title"], description=verdict["summary"], color=0xe74c3c,
            )
            embed.add_field(name="Capa", value=verdict["detail"], inline=False)
            embed.add_field(name="Diagnostico por capas", value=_probe_lines(probes), inline=False)
            if guardian and guardian.get("outage_secs"):
                embed.add_field(
                    name="ISP Guardian",
                    value=f"Corte de **{int(guardian['outage_secs'])}s** en curso · "
                          f"{guardian.get('reboots_in_window', 0)}/{guardian.get('max_reboots', '?')} reboots en ventana",
                    inline=False,
                )
            embed.set_footer(text=now.strftime('%d/%m/%Y %H:%M:%S'))
            await channel.send(embed=embed)
        return

    if network_down_layer:
        # Recuperacion: se informa cuanto duro y que capa habia fallado.
        dur = int((now - network_down_since).total_seconds()) if network_down_since else 0
        embed = discord.Embed(
            title="🌐 Red Restaurada",
            description=f"Se recupero la capa **{network_down_layer}** tras **{dur // 60}m {dur % 60}s**.",
            color=0x2ecc71,
        )
        embed.add_field(name="Estado actual", value=_probe_lines(probes), inline=False)
        embed.set_footer(text=now.strftime('%d/%m/%Y %H:%M:%S'))
        await channel.send(embed=embed)
        network_down_layer = None
        network_down_since = None

@tasks.loop(minutes=2)
async def watch_docker_loops():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or not shutil.which("docker"):
        return
    ok, out = await asyncio.to_thread(
        docker_cmd, ["ps", "--filter", "status=restarting", "--format", "{{.Names}}"]
    )
    if not ok or not out:
        return
    now = datetime.now()
    # Se cuenta por SERVICIO, no por task: bajo Swarm cada reintento del loop es
    # una task con id nuevo, asi que la memoria de intentos por nombre de
    # contenedor nunca acertaba y el bot reiniciaba para siempre.
    for task in group_services([
        {"name": n, "service": service_of(n), "status": "Restarting",
         "image": "", "ports": "", "running": False}
        for n in out.splitlines() if n.strip()
    ]):
        svc = task["service"]
        cur = task["current"]
        if svc in docker_heal_attempts and (now - docker_heal_attempts[svc] > HEAL_TIMEOUT):
            del docker_heal_attempts[svc]
        if svc not in docker_heal_attempts:
            await asyncio.to_thread(restart_service, svc, cur)
            docker_heal_attempts[svc] = now
            embed = discord.Embed(title="🩹 Auto-Healing", description=f"`{svc}` reiniciado.", color=0x3498db)
            embed.set_footer(text=now.strftime('%H:%M:%S'))
            await channel.send(embed=embed)
            stats_counter["docker_alerts"] += 1
            return
        if now - last_docker_alert.get(svc, datetime.min) > DOCKER_LOOP_COOLDOWN:
            _, log = await asyncio.to_thread(docker_cmd, ["logs", "--tail", "5", cur["name"]], 30)
            embed = discord.Embed(title="🔄 Docker Loop - Fix Fallido", description=f"`{svc}` sigue reiniciando.", color=0xe67e22)
            embed.add_field(name="Log", value=f"```\n{log[:500]}\n```", inline=False)
            await channel.send(embed=embed)
            last_docker_alert[svc] = now
            stats_counter["docker_alerts"] += 1

@tasks.loop(minutes=5)
async def watch_docker_resources():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or not shutil.which("docker"):
        return
    containers = await asyncio.to_thread(get_docker_stats)
    for c in containers:
        if c["cpu"] > 90 or c["mem_pct"] > 90:
            embed = discord.Embed(title=f"🐳 Alto Consumo: {c['service']}", color=0xe67e22)
            if c["cpu"] > 90:
                embed.add_field(name="CPU", value=f"**{c['cpu']:.1f}%**", inline=True)
            if c["mem_pct"] > 90:
                embed.add_field(name="RAM", value=f"**{c['mem_pct']:.1f}%** ({c['mem_usage']})", inline=True)
            embed.set_footer(text=datetime.now().strftime('%H:%M:%S'))
            await channel.send(embed=embed)

@tasks.loop(hours=24)
async def watch_backups():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or not BACKUP_PATH or not os.path.exists(BACKUP_PATH):
        return
    # FIX: Borg no crea archivos nuevos, actualiza index.* — chequeamos su mtime
    last_mtime, index_file = await asyncio.to_thread(get_borg_last_backup, BACKUP_PATH)
    if last_mtime is None:
        await channel.send(embed=discord.Embed(
            title="🚨 Repo Borg sin índice",
            description=f"No se encontró `index.*` en `{BACKUP_PATH}`.",
            color=0xff0000
        ))
        return
    age = datetime.now() - last_mtime
    if age > timedelta(hours=25):
        embed = discord.Embed(title="🚨 Backup Desactualizado", color=0xff0000)
        embed.add_field(name="Índice", value=f"`{os.path.basename(index_file)}`", inline=True)
        embed.add_field(name="Antigüedad", value=str(age).split('.')[0], inline=True)
        embed.add_field(name="Última modificación", value=last_mtime.strftime('%d/%m/%Y %H:%M'), inline=True)
        await channel.send(embed=embed)

@tasks.loop(hours=6)
async def guardian_report():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return

    avg_cpu = sum(history_cpu) / len(history_cpu) if history_cpu else 0
    avg_ram = sum(history_ram) / len(history_ram) if history_ram else 0
    disk_current = list(history_disk)[-1] if history_disk else 0
    swap_current = list(history_swap)[-1] if history_swap else 0

    score = 100
    if avg_cpu > 50: score -= (avg_cpu - 50)
    if avg_ram > 70: score -= (avg_ram - 70)
    score -= stats_counter["docker_alerts"] * 15
    score -= stats_counter["service_alerts"] * 20
    score -= stats_counter["fail2ban_bans"] * 5
    if stats_counter["ssh_fails"] > SSH_FAIL_THRESHOLD: score -= 10
    score = max(0, int(score))

    estado = "🟢 Estable" if score >= 80 else "🟡 Degradado" if score >= 50 else "🔴 Critico"

    embed = discord.Embed(title=f"📊 Guardian Report — {SERVER_NAME}", color=health_color(score), timestamp=datetime.now())
    embed.add_field(name="🏆 Health", value=f"{health_emoji(score)} **{score}/100**", inline=True)
    embed.add_field(name="📡 Estado", value=estado, inline=True)
    embed.add_field(name="\u200b", value="\u200b", inline=True)
    embed.add_field(name="🖥 CPU Promedio", value=make_bar(avg_cpu), inline=False)
    embed.add_field(name="🧠 RAM Promedio", value=make_bar(avg_ram), inline=False)
    embed.add_field(name="💾 Disco", value=make_bar(disk_current), inline=False)
    if swap_current > 0:
        embed.add_field(name="🔄 Swap", value=make_bar(swap_current), inline=False)
    embed.add_field(name="📈 Tend. Disco", value=predict_resource(history_disk), inline=True)
    embed.add_field(name="📈 Tend. RAM", value=predict_resource(history_ram), inline=True)
    embed.add_field(name="\u200b", value="\u200b", inline=True)
    embed.add_field(name="🔑 SSH OK", value=f"`{stats_counter['ssh_events']}`", inline=True)
    embed.add_field(name="❌ SSH Fail", value=f"`{stats_counter['ssh_fails']}`", inline=True)
    embed.add_field(name="🐳 Docker", value=f"`{stats_counter['docker_alerts']}`", inline=True)
    embed.add_field(name="⛔ Bans", value=f"`{stats_counter['fail2ban_bans']}`", inline=True)
    embed.add_field(name="☁️ Access", value=f"`{stats_counter['cloudflare_access']}`", inline=True)

    temps = get_temperatures()
    if temps:
        temp_lines = [f"`{k}`: **{v:.0f}°C**" for k, v in sorted(temps.items(), key=lambda x: x[1], reverse=True)[:3]]
        embed.add_field(name="🌡 Temperaturas", value="\n".join(temp_lines), inline=False)
    if remote_arch is not None:
        if remote_last_snapshot:
            remote_temps = remote_last_snapshot.get("temperatures") or {}
            temp_text = (
                f" · Temp `{max(remote_temps.values()):.1f}°C`"
                if remote_temps else " · Temp `sin datos`"
            )
            embed.add_field(
                name=f"🛰 {_remote_name()}",
                value=(
                    f"{'🔴' if remote_consecutive_failures >= 2 else '🟢'} "
                    f"CPU `{remote_last_snapshot.get('cpu_percent', 0):.1f}%` · "
                    f"RAM `{remote_last_snapshot.get('ram_percent', 0):.1f}%` · "
                    f"Disco `{remote_last_snapshot.get('disk_percent', 0):.1f}%`"
                    f"{temp_text}"
                ),
                inline=False,
            )
        else:
            embed.add_field(
                name=f"🛰 {_remote_name()}",
                value="⚪ Aún sin muestra del agente remoto.",
                inline=False,
            )

    image_data, fleet_result = await asyncio.gather(
        get_chart_image(include_disk=True, last_n=60),
        get_guardian_fleet_image(),
        return_exceptions=True,
    )

    files = []
    embeds = [embed]

    if isinstance(image_data, Exception):
        print(
            f"WARN: no se pudo generar el grafico del Guardian Report: "
            f"{image_data}",
            file=sys.stderr,
        )
    elif image_data:
        files.append(discord.File(
            io.BytesIO(image_data), filename="guardian-report.png"
        ))
        embed.set_image(url="attachment://guardian-report.png")

    if isinstance(fleet_result, Exception):
        print(
            f"WARN: no se pudo adjuntar Grafana al Guardian Report: "
            f"{fleet_result}",
            file=sys.stderr,
        )
        embed.add_field(
            name="🌐 Grafana Fleet",
            value="⚠️ Captura no disponible en este envío.",
            inline=False,
        )
    elif fleet_result is not None:
        dashboard, fleet_pages = fleet_result
        total = len(fleet_pages)
        for index, fleet_image in enumerate(fleet_pages, start=1):
            filename = f"grafana-fleet-{index}.png"
            files.append(discord.File(
                io.BytesIO(fleet_image), filename=filename
            ))
            fleet_embed = discord.Embed(
                title=f"🌐 Grafana — {dashboard['title']}",
                description=f"Dashboard completo · página {index}/{total}",
                color=GRAFANA_ORANGE,
                timestamp=datetime.now(),
            )
            fleet_embed.set_image(url=f"attachment://{filename}")
            fleet_embed.set_footer(
                text=f"Fleet Overview · rango {GRAFANA_GUARDIAN_RANGE}"
            )
            embeds.append(fleet_embed)

    await channel.send(
        files=files or discord.utils.MISSING,
        embeds=embeds,
    )

    for k in stats_counter:
        stats_counter[k] = 0


@guardian_report.before_loop
async def wait_before_first_guardian_report():
    """Avoid a cold Chromium render immediately after every bot deploy."""
    await bot.wait_until_ready()
    if GRAFANA_GUARDIAN_START_DELAY:
        await asyncio.sleep(GRAFANA_GUARDIAN_START_DELAY)

# ==========================================
# COMANDOS
# ==========================================
@bot.group(name='arch', aliases=['mbp'], invoke_without_command=True)
async def arch_group(ctx):
    """Comandos del nodo Arch atendidos por el único Centinela central."""
    await _remote_status_command(ctx)


@arch_group.command(name='help', aliases=['ayuda'])
async def arch_help(ctx):
    embed = _remote_embed(
        f"🛰 Comandos remotos — {_remote_name()}",
        description=(
            "`!arch` / `!arch status` — panel de control\n"
            "`!arch top` — procesos por CPU y RAM\n"
            "`!arch who` — sesiones activas\n"
            "`!arch temps` — todos los sensores\n"
            "`!arch ports` — sockets en escucha\n"
            "`!arch smart` — salud del disco\n"
            "`!arch services` — servicios systemd\n"
            "`!arch ct` — contenedores, puertos y consumo\n"
            "`!arch logs <contenedor>` — últimas líneas\n"
            "`!arch restart <contenedor>` — reinicio permitido\n"
            "`!arch updates` — actualizaciones de Arch\n"
            "`!arch backups` — estado del Borg\n\n"
            "También funciona el formato `!status arch`, `!ct arch` o "
            "`!logs <contenedor> arch`."
        ),
    )
    await ctx.send(embed=embed)


@arch_group.command(name='status')
async def arch_status(ctx):
    await _remote_status_command(ctx)


@arch_group.command(name='top')
async def arch_top(ctx):
    await _remote_top_command(ctx)


@arch_group.command(name='who')
async def arch_who(ctx):
    await _remote_sessions_command(ctx)


@arch_group.command(name='temps')
async def arch_temps(ctx):
    await _remote_temps_command(ctx)


@arch_group.command(name='ports')
async def arch_ports(ctx):
    await _remote_ports_command(ctx)


@arch_group.command(name='smart')
async def arch_smart(ctx):
    await _remote_smart_command(ctx)


@arch_group.command(name='services')
async def arch_services(ctx):
    await _remote_services_command(ctx)


@arch_group.command(name='ct', aliases=['contenedores'])
async def arch_containers(ctx):
    await _remote_containers_command(ctx)


@arch_group.command(name='logs')
async def arch_logs(ctx, service: str = None):
    if not service:
        return await ctx.send("Uso: `!arch logs <contenedor>`.")
    await _remote_logs_command(ctx, service)


@arch_group.command(name='restart')
async def arch_restart(ctx, service: str = None):
    if not service:
        return await ctx.send("Uso: `!arch restart <contenedor>`.")
    await _remote_restart_command(ctx, service)


@arch_group.command(name='updates')
async def arch_updates(ctx):
    await _remote_updates_command(ctx)


@arch_group.command(name='backups')
async def arch_backups(ctx):
    await _remote_backups_command(ctx)


@bot.command(name='status')
async def server_status(ctx, host: str = None):
    if _is_remote_alias(host):
        return await _remote_status_command(ctx)
    msg = await ctx.send("📊 **Analizando...**")
    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    swap = psutil.swap_memory()
    uptime = subprocess.getoutput("uptime -p").replace("up ", "")
    net = psutil.net_io_counters()

    score = 100
    if cpu > 50: score -= (cpu - 50)
    if ram.percent > 80: score -= (ram.percent - 80)
    score -= stats_counter["docker_alerts"] * 15
    score = max(0, int(score))

    embed = discord.Embed(title=f"🎛 Panel de Control — {SERVER_NAME}", color=health_color(score), timestamp=datetime.now())
    embed.add_field(name="🏆 Health", value=f"{health_emoji(score)} **{score}/100**", inline=True)
    embed.add_field(name="⏱ Uptime", value=f"`{uptime}`", inline=True)
    embed.add_field(name="\u200b", value="\u200b", inline=True)
    embed.add_field(name="🖥 CPU", value=make_bar(cpu), inline=False)
    embed.add_field(name=f"🧠 RAM — {predict_resource(history_ram)}", value=f"{make_bar(ram.percent)}\n`{ram.used//1024**2} / {ram.total//1024**2} MB`", inline=False)
    embed.add_field(name=f"💾 Disco — {predict_resource(history_disk)}", value=f"{make_bar(disk.percent)}\n`{disk.used//1024**3} / {disk.total//1024**3} GB`", inline=False)
    if swap.total > 0:
        embed.add_field(name="🔄 Swap", value=f"{make_bar(swap.percent)}\n`{swap.used//1024**2} / {swap.total//1024**2} MB`", inline=False)
    embed.add_field(name="🌐 Red", value=f"↑ `{format_bytes(net.bytes_sent)}`   ↓ `{format_bytes(net.bytes_recv)}`", inline=False)

    temps = get_temperatures()
    if temps:
        max_temp = max(temps.values())
        hottest = max(temps, key=temps.get)
        t_emoji = "🔴" if max_temp > TEMP_ALERT_C else "🟡" if max_temp > 70 else "🟢"
        embed.add_field(name="🌡 Temp", value=f"{t_emoji} `{hottest}`: **{max_temp:.0f}°C**", inline=False)

    image_data = await get_chart_image()
    if image_data:
        file = discord.File(io.BytesIO(image_data), filename="chart.png")
        embed.set_image(url="attachment://chart.png")
        await ctx.send(file=file, embed=embed)
    else:
        await ctx.send(embed=embed)
    await msg.delete()

@bot.command(name='top')
async def top_processes(ctx, host: str = None):
    if _is_remote_alias(host):
        return await _remote_top_command(ctx)
    # Bajo demanda se toma una muestra corta y propia: da la foto de AHORA en
    # vez del promedio del ultimo minuto que usan las alertas. Va en un thread
    # porque duerme 1s entre las dos lecturas.
    await asyncio.to_thread(procmon.sampler.sample_now, 1.0)

    embed = discord.Embed(title=f"📊 Top Procesos — {SERVER_NAME}", color=0x3498db, timestamp=datetime.now())
    for label, sort in [("🖥 Por CPU", "cpu"), ("🧠 Por RAM", "ram")]:
        rows = procmon.format_top(procmon.sampler.top(8, sort), "cpu" if sort == "cpu" else "mem")
        embed.add_field(name=label, value=rows or "Sin datos", inline=False)
    embed.set_footer(text=f"CPU normalizado sobre {procmon.CPU_COUNT} nucleos")
    await ctx.send(embed=embed)

@bot.command(name='who')
async def who_online(ctx, host: str = None):
    if _is_remote_alias(host):
        return await _remote_sessions_command(ctx)
    sessions = get_active_sessions()
    embed = discord.Embed(title=f"👥 Sesiones Activas — {SERVER_NAME}", color=0x3498db, timestamp=datetime.now())
    if not sessions:
        embed.description = "No hay sesiones activas."
    else:
        for s in sessions[:10]:
            is_local = any(s["host"].startswith(sub) for sub in SAFE_SUBNETS) or s["host"] == "local"
            embed.add_field(
                name=f"{'🟢' if is_local else '🟡'} {s['user']}",
                value=f"IP: `{s['host']}`\nTTY: `{s['terminal']}`\nDesde: `{s['started']}`",
                inline=True
            )
    await ctx.send(embed=embed)

@bot.command(name='keys', aliases=['claves'])
async def show_keys(ctx, host: str = None):
    """Claves SSH que el nodo acepta, con el nombre que el bot les pone.

    Existe para poder auditar el mapa sin entrar al servidor: si un login
    aparece como "clave no reconocida", aca se ve si falta la clave en el
    `authorized_keys` o si simplemente falta etiquetarla.
    """
    remote = _is_remote_alias(host)
    directory = remote_key_directory if remote else local_key_directory
    name = _remote_name() if remote else SERVER_NAME
    if not directory.loaded:
        return await ctx.send(
            f"❌ El directorio de claves de **{name}** todavía no se cargó."
        )
    embed = discord.Embed(
        title=f"🔐 Claves autorizadas — {name}",
        description=(
            f"{len(directory)} clave(s) · cuentas leídas: "
            + (", ".join(f"`{user}`" for user in sorted(directory.covered_users))
               or "_ninguna_")
        ),
        color=0x3498db,
        timestamp=datetime.now(),
    )
    for fingerprint, entry in directory.items()[:20]:
        label, _ = directory.describe(fingerprint)
        users = ", ".join(sorted(directory.authorized_users(fingerprint))) or "?"
        embed.add_field(
            name=f"{label}",
            value=(
                f"`…{directory.short(fingerprint)}` · "
                f"`{entry.get('key_type', '?')}`\ncuentas: `{users}`"
            ),
            inline=True,
        )
    if not len(directory):
        embed.add_field(
            name="Sin datos",
            value=(
                "No se pudo leer ningún `authorized_keys`. Revisá "
                "`SSH_KEY_DIRECTORY_FILES` y los `BindReadOnlyPaths` del "
                "drop-in de systemd."
            ),
            inline=False,
        )
    await ctx.send(embed=embed)


@bot.command(name='temps')
async def show_temps(ctx, host: str = None):
    if _is_remote_alias(host):
        return await _remote_temps_command(ctx)
    temps = get_temperatures()
    embed = discord.Embed(title=f"🌡 Temperaturas — {SERVER_NAME}", color=0x3498db, timestamp=datetime.now())
    if not temps:
        embed.description = "No se pudieron leer sensores."
        embed.color = 0xe67e22
    else:
        for label, temp in sorted(temps.items(), key=lambda x: x[1], reverse=True):
            emoji = "🔴" if temp > TEMP_ALERT_C else "🟡" if temp > 70 else "🟢"
            bar_len = min(12, int(temp / 100 * 12))
            embed.add_field(name=f"{emoji} {label}", value=f"`{'█'*bar_len + '░'*(12-bar_len)}` **{temp:.0f}°C**", inline=False)
    await ctx.send(embed=embed)

@bot.command(name='ports')
async def show_ports(ctx, host: str = None):
    if _is_remote_alias(host):
        return await _remote_ports_command(ctx)
    ports = await asyncio.to_thread(get_open_ports)
    embed = discord.Embed(title=f"🔌 Puertos Abiertos — {SERVER_NAME}", color=0x3498db, timestamp=datetime.now())
    if not ports:
        embed.description = "No se detectaron puertos en escucha."
    else:
        lines = []
        for p in ports[:20]:
            exposure = "🌐" if p["ip"] in ("0.0.0.0", "::") else "🏠"
            lines.append(f"{exposure} `:{p['port']:<6}` → `{p['process']}`")
        embed.description = "\n".join(lines)
        embed.set_footer(text="🌐 = todas las interfaces  🏠 = solo local")
    await ctx.send(embed=embed)

@bot.command(name='smart')
async def show_smart(ctx, host: str = None):
    if _is_remote_alias(host):
        return await _remote_smart_command(ctx)
    msg = await ctx.send("🔍 **Leyendo SMART...**")
    result = await asyncio.to_thread(get_smart_health)
    if not result:
        return await msg.edit(content="❌ `smartctl` no encontrado. Instala `smartmontools`.")

    output, disk = result["output"], result["disk"]
    is_healthy = "PASSED" in output or "OK" in output
    embed = discord.Embed(title=f"💿 Disco — {disk}", color=0x2ecc71 if is_healthy else 0xff0000, timestamp=datetime.now())
    embed.add_field(name="Estado", value="✅ PASSED" if is_healthy else "🔴 ALERTA", inline=True)

    keywords = ["Percentage Used", "Available Spare", "Temperature", "Power On Hours",
                 "Data Units", "Reallocated_Sector", "Wear_Leveling", "Media_Wearout"]
    attr_lines = [f"`{l.strip()[:70]}`" for l in output.splitlines() if any(k in l for k in keywords)]
    if attr_lines:
        embed.add_field(name="Atributos", value="\n".join(attr_lines[:8]), inline=False)
    await msg.edit(content=None, embed=embed)

@bot.command(name='services')
async def show_services(ctx, host: str = None):
    if _is_remote_alias(host):
        return await _remote_services_command(ctx)
    if not WATCHED_SERVICES:
        return await ctx.send("❌ `WATCHED_SERVICES` no configurado en `.env`.")
    embed = discord.Embed(title=f"⚙️ Servicios — {SERVER_NAME}", color=0x3498db, timestamp=datetime.now())
    all_ok = True
    for svc in WATCHED_SERVICES:
        status = await asyncio.to_thread(get_service_status, svc)
        icons = {"active": "🟢", "inactive": "🔴", "failed": "💀"}
        icon = icons.get(status, "🟡")
        if status != "active":
            all_ok = False
        embed.add_field(name=f"{icon} {svc}", value=f"`{status}`", inline=True)
    embed.color = 0x2ecc71 if all_ok else 0xe74c3c
    await ctx.send(embed=embed)

@bot.command(name='logs')
async def docker_logs(ctx, service: str = None, host: str = None):
    if not service:
        return await ctx.send("Uso: `!logs <servicio>` — la lista sale de `!ct`.")
    if _is_remote_alias(host):
        return await _remote_logs_command(ctx, service)
    svc, task = await asyncio.to_thread(resolve_service, service)
    if not svc:
        return await ctx.send(f"❌ No encontre un servicio que matchee `{service}`. Mira `!ct`.")
    ok, raw = await asyncio.to_thread(docker_cmd, ["logs", "--tail", "25", task["name"]], 60)
    embed = discord.Embed(title=f"📋 Logs: {svc['service']}", color=0x2496ed, timestamp=datetime.now())
    embed.description = f"```\n{raw[-1800:] or 'Sin salida.'}\n```"
    embed.set_footer(text="Ultimas 25 lineas")
    await ctx.send(embed=embed)

@bot.command(name='restart')
async def docker_restart(ctx, service: str = None, host: str = None):
    if not service:
        return await ctx.send("Uso: `!restart <servicio>` — la lista sale de `!ct`.")
    if _is_remote_alias(host):
        return await _remote_restart_command(ctx, service)
    svc, task = await asyncio.to_thread(resolve_service, service)
    if not svc:
        return await ctx.send(f"❌ No encontre un servicio que matchee `{service}`. Mira `!ct`.")
    name = svc["service"]
    if ALLOWED_RESTART and name not in ALLOWED_RESTART:
        allowed = ", ".join(f"`{c}`" for c in ALLOWED_RESTART)
        return await ctx.send(f"❌ `{name}` no permitido.\nPermitidos: {allowed}")

    msg = await ctx.send(f"🔄 Reiniciando `{name}`...")
    ok, result = await asyncio.to_thread(restart_service, name, task)
    if ok:
        embed = discord.Embed(
            title=f"✅ Reiniciado: {name}",
            description=f"Por **{ctx.author.display_name}**.",
            color=0x2ecc71
        )
    else:
        embed = discord.Embed(title=f"❌ Error: {name}", description=f"```\n{result[:500]}\n```", color=0xff0000)
    await msg.edit(content=None, embed=embed)

@bot.command(name='ct', aliases=['contenedores'])
async def check_containers(ctx, host: str = None):
    """Estado en vivo de los contenedores.

    Se llama !ct y no !docker a proposito: !docker es del Updates-Bot, que maneja
    las actualizaciones de imagen de toda la flota. Este muestra runtime (Up,
    CPU, RAM, puertos), que aquel no cubre.
    """
    if _is_remote_alias(host):
        return await _remote_containers_command(ctx)
    if not shutil.which("docker"):
        return await ctx.send("🐳 Docker no instalado.")
    tasks_now = await asyncio.to_thread(list_tasks)
    if not tasks_now:
        return await ctx.send("🐳 Sin contenedores.")

    services = group_services(tasks_now)
    stats = await asyncio.to_thread(get_docker_stats)
    stats_map = {s["name"]: s for s in stats}

    down = sum(1 for s in services if not s["current"]["running"])
    embed = discord.Embed(
        title=f"🐳 Contenedores — {SERVER_NAME}",
        color=0xe74c3c if down else 0x2ecc71,
        timestamp=datetime.now()
    )
    for s in services[:15]:
        cur = s["current"]
        icons = {"Up": "🟢", "Restarting": "🔄", "Exited": "🔴"}
        icon = next((v for k, v in icons.items() if k in cur["status"]), "🟡")
        value = f"`{cur['status']}`\n`{cur['image']}`"
        if cur["ports"]:
            value += f"\n`{cur['ports'][:50]}`"
        st = stats_map.get(cur["name"])
        if st:
            value += f"\nCPU: `{st['cpu']:.1f}%` RAM: `{st['mem_pct']:.1f}%`"
        if s["stale"]:
            value += f"\n_{s['stale']} task(s) vieja(s) sin limpiar_"
        embed.add_field(name=f"{icon} {s['service']}", value=value, inline=True)
    if len(services) > 15:
        embed.set_footer(text=f"...y {len(services) - 15} servicio(s) mas")
    await ctx.send(embed=embed)

@bot.command(name='updates')
async def check_os_updates(ctx, host: str = None):
    if _is_remote_alias(host):
        return await _remote_updates_command(ctx)
    if DISTRO == "unknown":
        return await ctx.send("❌ Distro no soportada.")
    pkg_mgr = "pacman" if DISTRO == "arch" else "apt"
    msg = await ctx.send(f"🔄 **Sincronizando {pkg_mgr}...**")
    updates = await fetch_updates()
    if not updates:
        embed = discord.Embed(title="✅ Sistema Actualizado", color=0x2ecc71)
    else:
        embed = discord.Embed(title=f"📦 {len(updates)} Actualizaciones", color=0xe67e22)
        lines = [f"- **{p}**\n  `{o}` → `{n}`" for p, o, n in updates[:12]]
        if len(updates) > 12:
            lines.append(f"\n_...y {len(updates) - 12} mas._")
        embed.description = "\n".join(lines)
        embed.set_footer(text="sudo pacman -Syu" if DISTRO == "arch" else "sudo apt upgrade")
    await msg.edit(content=None, embed=embed)

@bot.command(name='backups')
async def check_backups(ctx, host: str = None):
    if _is_remote_alias(host):
        return await _remote_backups_command(ctx)
    if not BACKUP_PATH:
        return await ctx.send("❌ `BACKUP_PATH` no configurado.")
    if not os.path.exists(BACKUP_PATH):
        return await ctx.send(f"❌ `{BACKUP_PATH}` no existe.")
    # FIX: usar mtime del index.* de Borg en vez de buscar archivos nuevos
    last_mtime, index_file = await asyncio.to_thread(get_borg_last_backup, BACKUP_PATH)
    if last_mtime is None:
        return await ctx.send(f"❌ No se encontró `index.*` en `{BACKUP_PATH}`.")
    age = datetime.now() - last_mtime
    repo_size = await asyncio.to_thread(
        lambda: sum(os.path.getsize(os.path.join(r, f))
                    for r, _, fs in os.walk(BACKUP_PATH) for f in fs)
    )
    is_ok = age < timedelta(hours=25)
    embed = discord.Embed(title="💾 Backup Borg", color=0x2ecc71 if is_ok else 0xff0000)
    embed.add_field(name="Índice", value=f"`{os.path.basename(index_file)}`", inline=False)
    embed.add_field(name="Última ejecución", value=last_mtime.strftime('%d/%m/%Y %H:%M'), inline=True)
    embed.add_field(name="Antigüedad", value=str(age).split('.')[0], inline=True)
    embed.add_field(name="Tamaño repo", value=format_bytes(repo_size), inline=True)
    embed.add_field(name="Estado", value="✅ Al día" if is_ok else "🔴 Desactualizado", inline=False)
    await ctx.send(embed=embed)

# ==========================================
# COMANDO GRAFANA (paneles del dashboard en el bot)
# ==========================================
def load_speed_history():
    """Historial de mediciones. En disco porque la referencia sirve justamente
    despues de un reinicio del bot: una mediana que se pierde en cada deploy no
    es una linea base."""
    try:
        with open(SPEEDTEST_HISTORY) as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def save_speed_measure(result):
    hist = load_speed_history()
    hist.append({
        "ts": datetime.now().isoformat(timespec="seconds"),
        "down": round(result["down_mbps"], 2),
        "up": round(result["up_mbps"], 2),
        "ping": round(result["ping_ms"], 1),
    })
    hist = hist[-SPEEDTEST_HISTORY_MAX:]
    try:
        with open(SPEEDTEST_HISTORY, "w") as fh:
            json.dump(hist, fh)
    except OSError:
        pass
    return hist


def speed_embed(result, verdict):
    if result.get("error"):
        return discord.Embed(title="📉 Speedtest fallo", description=result["error"], color=0xe74c3c)
    color = 0x2ecc71
    if verdict and verdict["verdict"] == "slow":
        color = 0xe74c3c
    elif verdict and verdict["verdict"] == "degraded":
        color = 0xe67e22
    embed = discord.Embed(title=f"📡 Speedtest — {SERVER_NAME}", color=color, timestamp=datetime.now())
    embed.add_field(name="⬇ Bajada", value=f"**{result['down_mbps']:.1f}** Mbps", inline=True)
    embed.add_field(name="⬆ Subida", value=f"**{result['up_mbps']:.1f}** Mbps", inline=True)
    embed.add_field(name="⏱ Ping", value=f"**{result['ping_ms']:.0f}** ms", inline=True)
    if verdict:
        embed.add_field(name="Contra tu linea base", value=verdict["msg"], inline=False)
    # El servidor se muestra siempre: sin saber contra que se midio, el numero
    # no significa nada (los mas cercanos que ofrece estan a 3400 km).
    embed.set_footer(text=f"vs {result['server']} · {result['distance_km']:.0f} km · {result['isp']}")
    return embed


async def do_speedtest():
    """Corre el speedtest fuera del event loop y actualiza la linea base."""
    global speedtest_running
    if speedtest_running:
        return None, None
    speedtest_running = True
    try:
        result = await asyncio.to_thread(netdiag.run_speedtest)
    finally:
        speedtest_running = False
    if result.get("error"):
        return result, None
    history = [h["down"] for h in load_speed_history()]
    verdict = netdiag.evaluate_speed(result, history)
    save_speed_measure(result)
    return result, verdict


@bot.command(name='alarmas', aliases=['alarms'])
async def show_alarms(ctx):
    """Estado de todas las alarmas, como la consola de CloudWatch."""
    icono = {OK: "🟢", ALARM: "🔴", NO_DATA: "⚪"}
    embed = discord.Embed(title=f"🚨 Alarmas — {SERVER_NAME}", color=0x3498db, timestamp=datetime.now())
    en_alarma = [a for a in alarm_engine.snapshot() if a["state"] == ALARM]
    embed.color = 0xff0000 if en_alarma else 0x2ecc71

    filas = []
    for a in alarm_engine.snapshot():
        valor = f"{a['value']:.1f}{a['unit']}" if a["value"] is not None else "sin dato"
        filas.append(f"{icono.get(a['state'], '⚪')} `{a['name']:<6}` {valor:>10} / umbral {a['threshold']}{a['unit']}")
    embed.add_field(name="Estado", value="\n".join(filas), inline=False)

    if alerts.QUIET_ENABLED:
        activo = " (activo ahora)" if alerts.in_quiet_hours() else ""
        embed.add_field(
            name="🌙 Modo silencio",
            value=f"{alerts.QUIET_START:02d}:00–{alerts.QUIET_END:02d}:00 · solo alertas críticas{activo}",
            inline=False,
        )
    embed.set_footer(text="Las acciones se proponen; ninguna se ejecuta sola.")
    await ctx.send(embed=embed)


@bot.command(name='red', aliases=['net', 'diag'])
async def network_diag(ctx):
    """Diagnostico de red por capas: enlace, WAN, DNS, HTTP y ONU."""
    msg = await ctx.send("🔎 Diagnosticando la red por capas...")
    probes, guardian = await asyncio.to_thread(netdiag.run_all_probes)
    verdict = netdiag.diagnose(probes)

    embed = discord.Embed(
        title=verdict["title"],
        description=verdict["summary"],
        color=0x2ecc71 if verdict["healthy"] else 0xe74c3c,
        timestamp=datetime.now(),
    )
    embed.add_field(name="Capas", value=_probe_lines(probes), inline=False)

    if guardian:
        estado = "🟢 OK" if guardian.get("wan_up") else "🔴 caido"
        linea = [f"WAN {estado} · ONU {'🟢' if guardian.get('onu_up') else '🔴'}"]
        if guardian.get("outage_secs"):
            linea.append(f"corte en curso: {int(guardian['outage_secs'])}s")
        linea.append(f"reboots en ventana: {guardian.get('reboots_in_window', 0)}/{guardian.get('max_reboots', '?')}")
        embed.add_field(name="ISP Guardian (solo lectura)", value=" · ".join(linea), inline=False)

        # "En verbo pasado": cuando volvio, a que hora se cayo y cuanto duro.
        cortes = [e for e in (guardian.get("events") or []) if e.get("type") == "wan_up"][-5:]
        if cortes:
            embed.add_field(
                name="Ultimos cortes",
                value="\n".join(f"`{e.get('iso', '?')}` {e.get('msg', '')}" for e in reversed(cortes)),
                inline=False,
            )
    await msg.delete()
    await ctx.send(embed=embed)


@bot.command(name='speedtest', aliases=['velocidad'])
async def speedtest_cmd(ctx):
    """Mide la velocidad real del enlace contra la linea base historica."""
    if not netdiag.speedtest_available():
        await ctx.send("⚠️ `speedtest-cli` no esta instalado en este host.")
        return
    now = datetime.now()
    restante = SPEEDTEST_COOLDOWN - (now - last_alert_time["speedtest"])
    if restante > timedelta(0):
        await ctx.send(f"⏳ Esperá {int(restante.total_seconds() // 60)}m: cada corrida usa ~40 MB del enlace que estamos midiendo.")
        return
    if speedtest_running:
        await ctx.send("⏳ Ya hay un speedtest en curso.")
        return
    last_alert_time["speedtest"] = now

    msg = await ctx.send("📡 Midiendo (~25s)...")
    result, verdict = await do_speedtest()
    await msg.delete()
    await ctx.send(embed=speed_embed(result, verdict))


@tasks.loop(hours=SPEEDTEST_EVERY_H)
async def watch_speed():
    """Mide periodicamente para construir la linea base.

    Solo avisa cuando el enlace esta MUY por debajo de lo normal: el objetivo es
    tener referencia historica, no postear un embed cada seis horas.
    """
    if not SPEEDTEST_ENABLED or not netdiag.speedtest_available():
        return
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return
    # Medir con la red caida da un numero sin sentido y encima ensucia la mediana.
    probes, _ = await asyncio.to_thread(netdiag.run_all_probes)
    if not netdiag.diagnose(probes)["healthy"]:
        return

    result, verdict = await do_speedtest()
    if not result or result.get("error") or not verdict:
        return
    now = datetime.now()
    if verdict["verdict"] == "slow" and (now - last_alert_time["slow"] > ALERT_COOLDOWN):
        last_alert_time["slow"] = now
        embed = speed_embed(result, verdict)
        embed.title = "🐌 Internet lento"
        await channel.send(embed=embed)


def _chunk_fields(embed, lines, name="​"):
    """Agrega 'lines' al embed respetando el limite de 1024 char por field."""
    chunk = ""
    for ln in lines:
        if len(chunk) + len(ln) + 1 > 1000:
            embed.add_field(name=name, value=chunk, inline=False)
            chunk = ""
        chunk += ln + "\n"
    if chunk:
        embed.add_field(name=name, value=chunk, inline=False)


@bot.command(name='grafana', aliases=['gf', 'dash'])
async def grafana_cmd(ctx, dashboard: str = None, panel: str = None, rng: str = None):
    """Ver los graficos de Grafana en Discord (descubrimiento 100% dinamico).

    Uso:
      !grafana                    -> lista los dashboards
      !grafana <dashboard>        -> lista los paneles de ese dashboard
      !grafana <dashboard> <panel> [rango]  -> renderiza ese panel (imagen exacta)
      !grafana <dashboard> full [rango]      -> renderiza el dashboard completo
    <dashboard> = uid o parte del titulo · <panel> = id o parte del titulo
    [rango] = 15m | 6h | 24h | 7d (default: GRAFANA_DEFAULT_RANGE)
    """
    if grafana_client is None:
        return await ctx.send(
            "❌ Feature de Grafana no configurada. Definí `GRAFANA_URL` y `GRAFANA_TOKEN` en `.env`."
        )
    try:
        # Nivel 0: listar dashboards
        if not dashboard:
            dashboards = await grafana_client.list_dashboards()
            if not dashboards:
                return await ctx.send("No hay dashboards en Grafana.")
            embed = discord.Embed(
                title="📊 Dashboards de Grafana",
                description="Usá `!grafana <dashboard>` para ver sus paneles.",
                color=GRAFANA_ORANGE,
            )
            by_folder = {}
            for d in dashboards:
                by_folder.setdefault(d['folder'], []).append(d)
            for folder, items in by_folder.items():
                val = "\n".join(f"`{d['uid']}` — {d['title']}" for d in items)
                embed.add_field(name=f"📁 {folder}", value=val, inline=False)
            embed.set_footer(text="!grafana <dashboard> [panel] [rango]")
            return await ctx.send(embed=embed)

        # Resolver dashboard por uid o titulo
        matches = await grafana_client.find_dashboards(dashboard)
        if not matches:
            return await ctx.send(f"❌ No encontré un dashboard que matchee `{dashboard}`.")
        if len(matches) > 1:
            opts = "\n".join(f"`{d['uid']}` — {d['title']}" for d in matches[:10])
            return await ctx.send(f"🤔 `{dashboard}` es ambiguo:\n{opts}\nEspecificá el `uid`.")
        info = await grafana_client.get_dashboard(matches[0]['uid'])

        # Nivel 1: listar paneles del dashboard
        if not panel:
            embed = discord.Embed(
                title=f"📊 {info['title']}",
                description=(f"`{len(info['panels'])}` paneles · "
                             f"`!grafana {info['uid']} <id|nombre> [rango]`"),
                color=GRAFANA_ORANGE,
            )
            lines = [f"`{p['id']:>3}` · {p['type'][:11]:<11} · {p['title']}" for p in info['panels'][:40]]
            _chunk_fields(embed, lines)
            if len(info['panels']) > 40:
                embed.set_footer(text=f"...y {len(info['panels']) - 40} más · `full` = dashboard completo")
            else:
                embed.set_footer(text="Tip: `!grafana <dash> full` → dashboard completo")
            return await ctx.send(embed=embed)

        from_expr, to_expr = parse_range(rng, GRAFANA_DEFAULT_RANGE)
        range_label = rng or GRAFANA_DEFAULT_RANGE

        # Nivel 2b: dashboard completo
        if panel.lower() in ('full', 'all', '*'):
            msg = await ctx.send(f"🖼️ Renderizando **{info['title']}** completo...")
            img = await grafana_client.render_dashboard(
                info['uid'], info['slug'], from_expr, to_expr,
                GRAFANA_DASH_W, GRAFANA_DASH_H, GRAFANA_THEME, GRAFANA_TZ,
            )
            fname = f"{info['slug']}.png"
            file = discord.File(io.BytesIO(img), filename=fname)
            embed = discord.Embed(title=f"📊 {info['title']}", color=GRAFANA_ORANGE, timestamp=datetime.now())
            embed.set_image(url=f"attachment://{fname}")
            embed.set_footer(text=f"Grafana · dashboard completo · rango {range_label}")
            await ctx.send(file=file, embed=embed)
            return await msg.delete()

        # Nivel 2a: panel individual
        found = grafana_client.resolve_panel(info['panels'], panel)
        if not found:
            return await ctx.send(
                f"❌ No encontré el panel `{panel}` en **{info['title']}**. "
                f"Listá con `!grafana {info['uid']}`."
            )
        if len(found) > 1:
            opts = "\n".join(f"`{p['id']}` — {p['title']}" for p in found[:10])
            return await ctx.send(f"🤔 `{panel}` matchea varios paneles:\n{opts}\nUsá el `id`.")
        target = found[0]
        msg = await ctx.send(f"🖼️ Renderizando **{target['title']}**...")
        img = await grafana_client.render_panel(
            info['uid'], info['slug'], target['id'], from_expr, to_expr,
            GRAFANA_PANEL_W, GRAFANA_PANEL_H, GRAFANA_THEME, GRAFANA_TZ,
        )
        fname = f"panel_{target['id']}.png"
        file = discord.File(io.BytesIO(img), filename=fname)
        embed = discord.Embed(
            title=f"{info['title']} — {target['title']}",
            color=GRAFANA_ORANGE, timestamp=datetime.now(),
        )
        embed.set_image(url=f"attachment://{fname}")
        embed.set_footer(text=f"Grafana · panel {target['id']} ({target['type']}) · rango {range_label}")
        await ctx.send(file=file, embed=embed)
        await msg.delete()
    except GrafanaError as e:
        await ctx.send(f"❌ Grafana: {e}")
    except Exception as e:
        await ctx.send(f"❌ Error inesperado: `{e}`")


# --- START ---
async def shutdown():
    channel = bot.get_channel(CHANNEL_ID)
    if channel:
        await channel.send(embed=discord.Embed(title="🔴 Sistema Offline", description=f"{SERVER_NAME} apagandose.", color=0xe74c3c))
    country_resolver.close()
    await bot.close()

def signal_handler(s, f):
    bot.loop.create_task(shutdown())

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
if __name__ == "__main__":
    bot.run(TOKEN)
