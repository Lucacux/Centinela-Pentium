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
from grafana import GrafanaClient, GrafanaError, parse_range

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
last_alert_time = {
    "cpu": datetime.min, "ram": datetime.min, "disk": datetime.min,
    "swap": datetime.min, "temp": datetime.min, "network": datetime.min,
    "bruteforce": datetime.min,
}
ALERT_COOLDOWN = timedelta(hours=1)
last_docker_alert = {}
docker_heal_attempts = {}
DOCKER_LOOP_COOLDOWN = timedelta(minutes=30)
HEAL_TIMEOUT = timedelta(hours=1)

cpu_high_streak = 0
ram_high_streak = 0

ssh_fail_timestamps = deque(maxlen=500)
last_service_status = {}
network_was_down = False

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

def get_running_packages():
    exe_paths = set()
    try:
        for proc in psutil.process_iter(['exe']):
            try:
                exe = proc.info['exe']
                if exe and exe.startswith("/usr") and os.path.exists(exe):
                    exe_paths.add(exe)
            except Exception:
                continue
    except Exception:
        pass

    running_packages = set()
    for exe in exe_paths:
        if DISTRO == "arch":
            result = subprocess.getoutput(f"pacman -Qo {exe} 2>/dev/null")
            if "is owned by" in result:
                try:
                    pkg = result.split("is owned by")[1].strip().split()[0]
                    running_packages.add(pkg)
                except IndexError:
                    continue
        elif DISTRO == "debian":
            result = subprocess.getoutput(f"dpkg -S {exe} 2>/dev/null")
            if ":" in result and "no path found" not in result:
                running_packages.add(result.split(":")[0].strip())
    return running_packages

def get_system_cves():
    if DISTRO == "arch":
        if not shutil.which("arch-audit"):
            return None
        return subprocess.getoutput("arch-audit")
    elif DISTRO == "debian":
        if not shutil.which("debsecan"):
            return None
        suite = subprocess.getoutput("lsb_release -sc 2>/dev/null").strip()
        if not suite:
            return None
        return subprocess.getoutput(f"debsecan --suite {suite} --format detail")
    return None

def parse_cve_output(output):
    vulns = []
    if DISTRO == "arch":
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if "Critical" in line or "High" in line:
                vulns.append(f"🔴 {line}")
    elif DISTRO == "debian":
        running = get_running_packages()
        curr = {}
        for line in output.splitlines():
            if line.startswith("CVE-"):
                curr = {"id": line.split()[0], "urgency": "low"}
                if "urgency:" in line:
                    curr["urgency"] = line.split("urgency:")[1].split(")")[0].strip()
            elif curr and line.startswith("  "):
                pkg = line.strip()
                if pkg in running and curr.get("urgency") in ["high", "critical"]:
                    vulns.append(f"🔴 **{pkg}**: `{curr['id']}`")
    return vulns

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

def get_top_processes(n=8, sort_by="cpu"):
    procs = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            info = proc.info
            if info['cpu_percent'] is not None:
                procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    key = 'cpu_percent' if sort_by == "cpu" else 'memory_percent'
    procs.sort(key=lambda p: p.get(key, 0), reverse=True)
    return procs[:n]

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

def check_network():
    try:
        result = subprocess.run(["ping", "-c", "1", "-W", "3", "1.1.1.1"], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False

def get_service_status(service_name):
    return subprocess.getoutput(f"systemctl is-active {service_name} 2>/dev/null").strip()

def get_docker_stats():
    if not shutil.which("docker"):
        return []
    raw = subprocess.getoutput(
        "docker stats --no-stream --format '{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}' 2>/dev/null"
    )
    containers = []
    for line in raw.splitlines():
        parts = line.split('|')
        if len(parts) < 4:
            continue
        try:
            containers.append({
                "name": parts[0].strip(),
                "cpu": float(parts[1].strip().rstrip('%')),
                "mem_usage": parts[2].strip(),
                "mem_pct": float(parts[3].strip().rstrip('%'))
            })
        except ValueError:
            continue
    return containers

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

# ==========================================
# EVENTOS Y TAREAS
# ==========================================
@bot.event
async def on_ready():
    print(f"Bot Centinela ONLINE: {bot.user}")
    for task in [collect_history, watch_resources, watch_docker_loops, watch_docker_resources, guardian_report, watch_network]:
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
            "`!docker`    Contenedores Docker\n"
            "`!services`  Servicios systemd\n"
            "`!logs <c>`  Logs de un contenedor\n"
            "`!restart <c>` Reiniciar contenedor\n\n"
            "**Mantenimiento**\n"
            "`!updates`   Actualizaciones\n"
            "`!cve`       Auditoria de seguridad\n"
            "`!backups`   Estado de backups"
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
    global cpu_high_streak, ram_high_streak
    cpu = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory().percent
    disk = psutil.disk_usage('/').percent
    swap = psutil.swap_memory().percent

    history_time.append(datetime.now())
    history_cpu.append(cpu)
    history_ram.append(ram)
    history_disk.append(disk)
    history_swap.append(swap)

    cpu_high_streak = cpu_high_streak + 1 if cpu > 90 else 0
    ram_high_streak = ram_high_streak + 1 if ram > 90 else 0

@tasks.loop(minutes=2)
async def watch_resources():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return
    now = datetime.now()
    disk = psutil.disk_usage('/').percent
    swap = psutil.swap_memory()

    if cpu_high_streak >= 3 and (now - last_alert_time["cpu"] > ALERT_COOLDOWN):
        avg_cpu = sum(list(history_cpu)[-3:]) / 3
        embed = discord.Embed(title="🔥 CPU CRITICA", description=f"**{cpu_high_streak} min** por encima del 90%.", color=0xe74c3c)
        embed.add_field(name="Uso promedio", value=make_bar(avg_cpu), inline=False)
        top = get_top_processes(3, "cpu")
        if top:
            embed.add_field(name="Top procesos", value="\n".join(f"`{p['name'][:20]}` — {p['cpu_percent']:.0f}%" for p in top), inline=False)
        embed.set_footer(text=now.strftime('%d/%m/%Y %H:%M:%S'))
        await channel.send(embed=embed)
        last_alert_time["cpu"] = now

    if ram_high_streak >= 2 and (now - last_alert_time["ram"] > ALERT_COOLDOWN):
        avg_ram = sum(list(history_ram)[-2:]) / 2
        embed = discord.Embed(title="⚠ RAM ALTA", description=f"**{ram_high_streak} min** por encima del 90%.", color=0xe67e22)
        embed.add_field(name="Uso promedio", value=make_bar(avg_ram), inline=False)
        top = get_top_processes(3, "ram")
        if top:
            embed.add_field(name="Top procesos", value="\n".join(f"`{p['name'][:20]}` — {p['memory_percent']:.1f}%" for p in top), inline=False)
        embed.set_footer(text=now.strftime('%d/%m/%Y %H:%M:%S'))
        await channel.send(embed=embed)
        last_alert_time["ram"] = now

    if disk > 90 and (now - last_alert_time["disk"] > ALERT_COOLDOWN):
        embed = discord.Embed(title="🚨 DISCO CRITICO", color=0xff0000)
        embed.add_field(name="Uso actual", value=make_bar(disk), inline=False)
        embed.set_footer(text=now.strftime('%d/%m/%Y %H:%M:%S'))
        await channel.send(embed=embed)
        last_alert_time["disk"] = now

    if swap.percent > SWAP_ALERT_PCT and (now - last_alert_time["swap"] > ALERT_COOLDOWN):
        embed = discord.Embed(title="⚠️ SWAP en Uso", description=f"**{swap.percent:.0f}%** ({format_bytes(swap.used)})", color=0xe67e22)
        embed.set_footer(text=now.strftime('%d/%m/%Y %H:%M:%S'))
        await channel.send(embed=embed)
        last_alert_time["swap"] = now

    temps = get_temperatures()
    if temps:
        max_temp = max(temps.values())
        if max_temp > TEMP_ALERT_C and (now - last_alert_time["temp"] > ALERT_COOLDOWN):
            hottest = max(temps, key=temps.get)
            embed = discord.Embed(title="🌡️ TEMPERATURA CRITICA", description=f"**{hottest}**: **{max_temp:.0f}°C** (umbral: {TEMP_ALERT_C}°C)", color=0xff0000)
            embed.set_footer(text=now.strftime('%d/%m/%Y %H:%M:%S'))
            await channel.send(embed=embed)
            last_alert_time["temp"] = now

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

@tasks.loop(minutes=3)
async def watch_network():
    global network_was_down
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        return
    is_up = await asyncio.to_thread(check_network)
    if not is_up and not network_was_down:
        network_was_down = True
    elif is_up and network_was_down:
        network_was_down = False
        embed = discord.Embed(title="🌐 Red Restaurada", description="Conectividad recuperada.", color=0x2ecc71)
        embed.set_footer(text=datetime.now().strftime('%H:%M:%S'))
        await channel.send(embed=embed)

@tasks.loop(minutes=2)
async def watch_docker_loops():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or not shutil.which("docker"):
        return
    out = subprocess.getoutput("docker ps --filter status=restarting --format '{{.Names}}'")
    if not out:
        return
    now = datetime.now()
    for cont in out.splitlines():
        if cont in docker_heal_attempts and (now - docker_heal_attempts[cont] > HEAL_TIMEOUT):
            del docker_heal_attempts[cont]
        if cont not in docker_heal_attempts:
            subprocess.getoutput(f"docker restart {cont}")
            docker_heal_attempts[cont] = now
            embed = discord.Embed(title="🩹 Auto-Healing", description=f"`{cont}` reiniciado.", color=0x3498db)
            embed.set_footer(text=now.strftime('%H:%M:%S'))
            await channel.send(embed=embed)
            stats_counter["docker_alerts"] += 1
            return
        if now - last_docker_alert.get(cont, datetime.min) > DOCKER_LOOP_COOLDOWN:
            log = subprocess.getoutput(f"docker logs --tail 5 {cont} 2>&1")
            embed = discord.Embed(title="🔄 Docker Loop - Fix Fallido", description=f"`{cont}` sigue reiniciando.", color=0xe67e22)
            embed.add_field(name="Log", value=f"```\n{log[:500]}\n```", inline=False)
            await channel.send(embed=embed)
            last_docker_alert[cont] = now
            stats_counter["docker_alerts"] += 1

@tasks.loop(minutes=5)
async def watch_docker_resources():
    channel = bot.get_channel(CHANNEL_ID)
    if not channel or not shutil.which("docker"):
        return
    containers = await asyncio.to_thread(get_docker_stats)
    for c in containers:
        if c["cpu"] > 90 or c["mem_pct"] > 90:
            embed = discord.Embed(title=f"🐳 Alto Consumo: {c['name']}", color=0xe67e22)
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

    image_data = await get_chart_image(include_disk=True, last_n=60)
    if image_data:
        file = discord.File(io.BytesIO(image_data), filename="report.png")
        embed.set_image(url="attachment://report.png")
        await channel.send(file=file, embed=embed)
    else:
        await channel.send(embed=embed)

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
    for proc in psutil.process_iter(['cpu_percent']):
        pass
    await asyncio.sleep(1)

    embed = discord.Embed(title=f"📊 Top Procesos — {SERVER_NAME}", color=0x3498db, timestamp=datetime.now())
    for label, sort in [("🖥 Por CPU", "cpu"), ("🧠 Por RAM", "ram")]:
        top = get_top_processes(8, sort)
        key = 'cpu_percent' if sort == "cpu" else 'memory_percent'
        lines = [f"`{p['name'][:18]:<18}` {p[key]:>5.1f}% `{'█' * int(p[key] / 10)}`" for p in top]
        embed.add_field(name=label, value="\n".join(lines) or "Sin datos", inline=False)
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
async def docker_logs(ctx, container: str = None):
    if not container:
        return await ctx.send("Uso: `!logs <contenedor>`")
    if not shutil.which("docker"):
        return await ctx.send("❌ Docker no instalado.")
    raw = await asyncio.to_thread(subprocess.getoutput, f"docker logs --tail 25 {container} 2>&1")
    embed = discord.Embed(title=f"📋 Logs: {container}", color=0x2496ed, timestamp=datetime.now())
    embed.description = f"```\n{raw[-1800:]}\n```"
    embed.set_footer(text="Ultimas 25 lineas")
    await ctx.send(embed=embed)

@bot.command(name='restart')
async def docker_restart(ctx, container: str = None):
    if not container:
        return await ctx.send("Uso: `!restart <contenedor>`")
    if not shutil.which("docker"):
        return await ctx.send("❌ Docker no instalado.")
    if ALLOWED_RESTART and container not in ALLOWED_RESTART:
        allowed = ", ".join(f"`{c}`" for c in ALLOWED_RESTART)
        return await ctx.send(f"❌ `{container}` no permitido.\nPermitidos: {allowed}")

    msg = await ctx.send(f"🔄 Reiniciando `{container}`...")
    result = await asyncio.to_thread(subprocess.getoutput, f"docker restart {container} 2>&1")
    if container in result:
        embed = discord.Embed(title=f"✅ Reiniciado: {container}", description=f"Por **{ctx.author.display_name}**.", color=0x2ecc71)
    else:
        embed = discord.Embed(title=f"❌ Error: {container}", description=f"```\n{result[:500]}\n```", color=0xff0000)
    await msg.edit(content=None, embed=embed)

@bot.command(name='docker')
async def check_docker(ctx):
    if not shutil.which("docker"):
        return await ctx.send("🐳 Docker no instalado.")
    raw = subprocess.getoutput("docker ps -a --format '{{.Names}}|{{.Status}}|{{.Image}}|{{.Ports}}'")
    if not raw.strip():
        return await ctx.send("🐳 Sin contenedores.")

    stats = await asyncio.to_thread(get_docker_stats)
    stats_map = {s["name"]: s for s in stats}

    embed = discord.Embed(title="🐳 Contenedores Docker", color=0x2496ed, timestamp=datetime.now())
    for line in raw.splitlines()[:15]:
        parts = line.split('|')
        if len(parts) < 3:
            continue
        name, status, image = parts[0], parts[1], parts[2]
        ports = parts[3] if len(parts) > 3 else ""
        icons = {"Up": "🟢", "Restarting": "🔄", "Exited": "🔴"}
        icon = next((v for k, v in icons.items() if k in status), "🟡")
        value = f"`{status}`\n`{image}`"
        if ports:
            value += f"\n`{ports[:50]}`"
        s = stats_map.get(name)
        if s:
            value += f"\nCPU: `{s['cpu']:.1f}%` RAM: `{s['mem_pct']:.1f}%`"
        embed.add_field(name=f"{icon} {name}", value=value, inline=True)
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

@bot.command(name='cve')
async def manual_cve(ctx):
    if DISTRO == "arch":
        tool, install_cmd = "arch-audit", "sudo pacman -S arch-audit"
    elif DISTRO == "debian":
        tool, install_cmd = "debsecan", "sudo apt install debsecan"
    else:
        return await ctx.send("❌ Distro no soportada.")
    msg = await ctx.send(f"🔍 **Auditando con {tool}...**")
    output = await asyncio.to_thread(get_system_cves)
    if not output:
        return await msg.edit(content=f"❌ `{tool}` no instalado. Ejecuta: `{install_cmd}`")
    vulns = await asyncio.to_thread(parse_cve_output, output)
    if vulns:
        embed = discord.Embed(title="🚨 Vulnerabilidades", description="\n".join(vulns[:15]), color=0xff0000)
        embed.set_footer(text=f"{len(vulns)} encontrada(s)")
    else:
        embed = discord.Embed(title="✅ Sistema Seguro", description="Sin vulnerabilidades criticas.", color=0x2ecc71)
    await msg.edit(content=None, embed=embed)

# ==========================================
# COMANDO GRAFANA (paneles del dashboard en el bot)
# ==========================================
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
