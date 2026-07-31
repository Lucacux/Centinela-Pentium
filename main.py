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
GRAFANA_ORANGE = 0xF46800
GRAFANA_GUARDIAN_ENABLED = os.getenv(
    'GRAFANA_GUARDIAN_ENABLED', 'true'
).lower() in ('true', '1', 'yes')
GRAFANA_GUARDIAN_DASHBOARD = os.getenv(
    'GRAFANA_GUARDIAN_DASHBOARD', 'fleet-overview'
).strip()
GRAFANA_GUARDIAN_PANEL = os.getenv(
    'GRAFANA_GUARDIAN_PANEL', 'Estado de nodos'
).strip()
GRAFANA_GUARDIAN_RANGE = os.getenv(
    'GRAFANA_GUARDIAN_RANGE', '15m'
).strip()
GRAFANA_GUARDIAN_W = int(os.getenv('GRAFANA_GUARDIAN_WIDTH', '1200'))
GRAFANA_GUARDIAN_H = int(os.getenv('GRAFANA_GUARDIAN_HEIGHT', '700'))

grafana_client = (
    GrafanaClient(GRAFANA_URL, GRAFANA_TOKEN)
    if GRAFANA_URL and GRAFANA_TOKEN else None
)

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

stats_counter = {"ssh_events": 0, "ssh_fails": 0, "docker_alerts": 0, "service_alerts": 0}
# Solo para lo que NO pasa por el motor de alarmas (que lleva su propio
# cooldown por alarma): fuerza bruta SSH y el ritmo del speedtest.
last_alert_time = {
    "bruteforce": datetime.min, "speedtest": datetime.min, "slow": datetime.min,
}
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


ssh_fail_timestamps = deque(maxlen=500)
last_service_status = {}
# Capa culpable del ultimo corte ("wan", "dns", ...) o None si la red esta sana.
# Guardar la CAPA y no un bool permite avisar cuando la falla se MUEVE de lugar
# (p.ej. vuelve la WAN pero ahora lo roto es el DNS): con un bool eso pasaba
# desapercibido porque "seguia caido".
network_down_layer = None
network_down_since = None
speedtest_running = False

# ==========================================
# HELPERS VISUALES
# ==========================================
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
            raw = subprocess.getoutput(f"smartctl -H -A {disk} 2>/dev/null")
            return {"disk": disk, "output": raw}
    return None

def get_service_status(service_name):
    return subprocess.getoutput(f"systemctl is-active {service_name} 2>/dev/null").strip()

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
    try:
        parts = line.split()
        user = parts[parts.index("for") + 1]
        ip = parts[parts.index("from") + 1]
        is_local = any(ip.startswith(s) for s in SAFE_SUBNETS)
        embed = discord.Embed(title="🔑 Nuevo Login SSH", color=0x2ecc71 if is_local else 0xe67e22)
        embed.add_field(name="👤 Usuario", value=f"`{user}`", inline=True)
        embed.add_field(name="🌐 IP", value=f"`{ip}`", inline=True)
        embed.add_field(name="🏠 Origen", value="Red local" if is_local else "⚠️ IP externa", inline=True)
        embed.set_footer(text=datetime.now().strftime('%H:%M:%S'))
        await channel.send(embed=embed)
    except Exception:
        pass

async def _process_ssh_fail(channel, line):
    stats_counter["ssh_fails"] += 1
    now = datetime.now()
    ssh_fail_timestamps.append(now)

    cutoff = now - timedelta(seconds=SSH_FAIL_WINDOW)
    while ssh_fail_timestamps and ssh_fail_timestamps[0] < cutoff:
        ssh_fail_timestamps.popleft()

    recent_fails = len(ssh_fail_timestamps)
    if recent_fails >= SSH_FAIL_THRESHOLD and (now - last_alert_time["bruteforce"] > ALERT_COOLDOWN):
        ip = "desconocida"
        try:
            parts = line.split()
            if "from" in parts:
                ip = parts[parts.index("from") + 1]
        except Exception:
            pass

        embed = discord.Embed(
            title="🚨 Posible Brute Force SSH",
            description=f"**{recent_fails} intentos fallidos** en los ultimos {SSH_FAIL_WINDOW}s.",
            color=0xff0000
        )
        embed.add_field(name="🌐 Ultima IP", value=f"`{ip}`", inline=True)
        embed.add_field(name="🛡 Recomendacion", value="Revisar fail2ban / firewall", inline=True)
        embed.set_footer(text=now.strftime('%H:%M:%S'))
        await channel.send(embed=embed)
        last_alert_time["bruteforce"] = now

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
    """Captura el estado de la flota que acompana al Guardian Report."""
    if (
        grafana_client is None
        or not GRAFANA_GUARDIAN_ENABLED
        or not GRAFANA_GUARDIAN_DASHBOARD
        or not GRAFANA_GUARDIAN_PANEL
    ):
        return None

    from_expr, to_expr = parse_range(
        GRAFANA_GUARDIAN_RANGE, GRAFANA_DEFAULT_RANGE
    )
    return await grafana_client.render_panel_by_ref(
        GRAFANA_GUARDIAN_DASHBOARD,
        GRAFANA_GUARDIAN_PANEL,
        from_expr,
        to_expr,
        GRAFANA_GUARDIAN_W,
        GRAFANA_GUARDIAN_H,
        GRAFANA_THEME,
        GRAFANA_TZ,
    )

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
        status = get_service_status(svc)
        prev = last_service_status.get(svc)
        if prev is not None and prev == "active" and status != "active":
            embed = discord.Embed(title=f"🔴 Servicio Caido: {svc}", description=f"`{svc}` paso a **{status}**.", color=0xff0000)
            log = subprocess.getoutput(f"journalctl -u {svc} -n 5 --no-pager 2>/dev/null")
            if log:
                embed.add_field(name="Log", value=f"```\n{log[:500]}\n```", inline=False)
            await channel.send(embed=embed)
            stats_counter["service_alerts"] += 1
        elif prev is not None and prev != "active" and status == "active":
            embed = discord.Embed(title=f"🟢 Servicio Recuperado: {svc}", color=0x2ecc71)
            await channel.send(embed=embed)
        last_service_status[svc] = status

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

    temps = get_temperatures()
    if temps:
        temp_lines = [f"`{k}`: **{v:.0f}°C**" for k, v in sorted(temps.items(), key=lambda x: x[1], reverse=True)[:3]]
        embed.add_field(name="🌡 Temperaturas", value="\n".join(temp_lines), inline=False)

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
        dashboard, panel, fleet_image = fleet_result
        files.append(discord.File(
            io.BytesIO(fleet_image), filename="grafana-fleet.png"
        ))
        fleet_embed = discord.Embed(
            title=f"🌐 Grafana — {dashboard['title']}",
            description=panel["title"],
            color=GRAFANA_ORANGE,
            timestamp=datetime.now(),
        )
        fleet_embed.set_image(url="attachment://grafana-fleet.png")
        fleet_embed.set_footer(
            text=f"Fleet status · rango {GRAFANA_GUARDIAN_RANGE}"
        )
        embeds.append(fleet_embed)

    await channel.send(
        files=files or discord.utils.MISSING,
        embeds=embeds,
    )

    for k in stats_counter:
        stats_counter[k] = 0

# ==========================================
# COMANDOS
# ==========================================
@bot.command(name='status')
async def server_status(ctx):
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
async def top_processes(ctx):
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
async def who_online(ctx):
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

@bot.command(name='temps')
async def show_temps(ctx):
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
async def show_ports(ctx):
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
async def show_smart(ctx):
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
async def show_services(ctx):
    if not WATCHED_SERVICES:
        return await ctx.send("❌ `WATCHED_SERVICES` no configurado en `.env`.")
    embed = discord.Embed(title=f"⚙️ Servicios — {SERVER_NAME}", color=0x3498db, timestamp=datetime.now())
    all_ok = True
    for svc in WATCHED_SERVICES:
        status = get_service_status(svc)
        icons = {"active": "🟢", "inactive": "🔴", "failed": "💀"}
        icon = icons.get(status, "🟡")
        if status != "active":
            all_ok = False
        embed.add_field(name=f"{icon} {svc}", value=f"`{status}`", inline=True)
    embed.color = 0x2ecc71 if all_ok else 0xe74c3c
    await ctx.send(embed=embed)

@bot.command(name='logs')
async def docker_logs(ctx, service: str = None):
    if not service:
        return await ctx.send("Uso: `!logs <servicio>` — la lista sale de `!ct`.")
    svc, task = await asyncio.to_thread(resolve_service, service)
    if not svc:
        return await ctx.send(f"❌ No encontre un servicio que matchee `{service}`. Mira `!ct`.")
    ok, raw = await asyncio.to_thread(docker_cmd, ["logs", "--tail", "25", task["name"]], 60)
    embed = discord.Embed(title=f"📋 Logs: {svc['service']}", color=0x2496ed, timestamp=datetime.now())
    embed.description = f"```\n{raw[-1800:] or 'Sin salida.'}\n```"
    embed.set_footer(text="Ultimas 25 lineas")
    await ctx.send(embed=embed)

@bot.command(name='restart')
async def docker_restart(ctx, service: str = None):
    if not service:
        return await ctx.send("Uso: `!restart <servicio>` — la lista sale de `!ct`.")
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
async def check_containers(ctx):
    """Estado en vivo de los contenedores.

    Se llama !ct y no !docker a proposito: !docker es del Updates-Bot, que maneja
    las actualizaciones de imagen de toda la flota. Este muestra runtime (Up,
    CPU, RAM, puertos), que aquel no cubre.
    """
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
async def check_os_updates(ctx):
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
async def check_backups(ctx):
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
    await bot.close()

def signal_handler(s, f):
    bot.loop.create_task(shutdown())

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)
bot.run(TOKEN)
