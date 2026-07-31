"""Diagnostico de red por capas del Centinela.

Antes esto era `check_network()`: un `ping -c1 1.1.1.1` que devolvia un bool.
Ese bool colapsa cuatro fallas distintas en una sola ("se fue internet") y
ninguna de las cuatro se arregla igual:

  - se cayo el enlace local  -> el problema esta adentro de casa
  - se cayo el DNS           -> hay salida, no hay resolucion
  - no hay salida a WAN      -> el ISP o el ONU
  - hay ruta pero secuestrada-> captive portal / DPI del ISP

Este modulo prueba cada capa por separado y nombra la primera que falla.

Vive fuera de main.py por la misma razon que docker_ops.py: main.py llama a
bot.run() a nivel de modulo, asi que no se puede importar desde un test. Las
sondas hacen I/O, pero `diagnose()` es pura -- recibe los resultados ya
medidos, asi que la logica de decision se testea sin tocar la red.

El Centinela aca NO actua: solo observa y reporta. Quien reinicia el ONU es el
ISP Uplink Guardian; este modulo lo consulta como fuente de verdad para la capa
que el pentium no puede ver solo (si el ONU esta vivo o muerto).
"""
import json
import os
import shutil
import socket
import subprocess
import time

# --- Config (todo opcional: sin nada seteado el modulo usa defaults sanos) ---

# El nombre a resolver para probar DNS. Se evita algo con TTL agresivo o
# geo-balanceado para que la respuesta sea estable.
DNS_PROBE_NAME = os.getenv("NET_DNS_PROBE", "cloudflare.com")

# Resolver externo contra el que contrastar el resolver configurado. Es la unica
# forma de distinguir "mi resolver local esta roto" de "no hay DNS en ningun
# lado", y en esta red importa: el DNS configurado ES el gateway (192.168.2.1),
# asi que si el router muere las dos capas caen juntas.
DNS_EXTERNAL = os.getenv("NET_DNS_EXTERNAL", "1.1.1.1")

# IPs para probar WAN sin depender de DNS. Dos proveedores distintos: si un solo
# anycast esta caido no queremos declarar que se cayo internet.
WAN_IPS = [ip for ip in os.getenv("NET_WAN_IPS", "1.1.1.1,8.8.8.8").split(",") if ip.strip()]

# URL con TLS real. Detecta captive portal / proxy transparente: un portal
# responde 200 con HTML propio o rompe el handshake, no devuelve 204 vacio.
HTTP_PROBE_URL = os.getenv("NET_HTTP_PROBE", "https://www.gstatic.com/generate_204")
HTTP_PROBE_EXPECT = int(os.getenv("NET_HTTP_EXPECT", "204"))

# API del ISP Uplink Guardian (server-mbp). Sin esto el diagnostico funciona
# igual, solo pierde la capa ONU.
GUARDIAN_URL = os.getenv("ISP_GUARDIAN_URL", "").rstrip("/")

# Estados de una sonda.
OK = "ok"
FAIL = "fail"
SKIP = "skip"


class Probe:
    """Resultado de una sonda: estado + latencia + detalle legible."""

    def __init__(self, layer, state, detail="", ms=None):
        self.layer = layer
        self.state = state
        self.detail = detail
        self.ms = ms

    @property
    def ok(self):
        return self.state == OK

    @property
    def failed(self):
        return self.state == FAIL

    def __repr__(self):
        return f"<Probe {self.layer}={self.state} {self.detail!r}>"


# ==========================================
# SONDAS (hacen I/O; se corren en un thread)
# ==========================================

def _ping(host, count=2, wait=2):
    """Ping sin shell. Devuelve (ok, ms_promedio o None)."""
    t0 = time.monotonic()
    try:
        p = subprocess.run(
            ["ping", "-n", "-c", str(count), "-W", str(wait), host],
            capture_output=True, text=True, timeout=count * wait + 3,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False, None
    if p.returncode != 0:
        return False, None
    # "rtt min/avg/max/mdev = 1.234/2.345/..." -- si no parsea, el ping igual sirvio.
    for line in (p.stdout or "").splitlines():
        if "min/avg/max" in line and "=" in line:
            try:
                return True, float(line.split("=")[1].strip().split("/")[1])
            except (IndexError, ValueError):
                break
    return True, (time.monotonic() - t0) * 1000


def default_gateway():
    """IP del gateway por defecto, o None. Se lee de /proc para no depender de `ip`."""
    try:
        with open("/proc/net/route") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                # destino 00000000 = ruta default; flag 0x2 = RTF_GATEWAY
                if len(f) > 3 and f[1] == "00000000" and int(f[3], 16) & 2:
                    raw = int(f[2], 16)
                    return ".".join(str((raw >> (8 * i)) & 0xFF) for i in range(4))
    except (OSError, ValueError, IndexError):
        pass
    return None


# Puertos tipicos de un router domestico. Se usan solo para confirmar que el
# gateway esta vivo cuando filtra ICMP.
GATEWAY_TCP_PORTS = [int(p) for p in os.getenv("NET_GATEWAY_PORTS", "53,80,443").split(",") if p.strip()]


def neighbour_state(ip):
    """Estado ARP/NDP del vecino, o None si no hay entrada.

    `ip neigh` distingue REACHABLE (el kernel confirmo alcance bidireccional
    hace poco) de STALE (hubo entrada, puede estar vieja), y esa diferencia es
    justo la que necesitamos. Si no esta el binario, se cae a /proc/net/arp,
    que solo dice completa/incompleta.
    """
    if shutil.which("ip"):
        try:
            p = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=4)
            parts = (p.stdout or "").split()
            if parts:
                return parts[-1].upper()  # ultimo campo = estado
        except (subprocess.TimeoutExpired, OSError):
            pass
    try:
        with open("/proc/net/arp") as fh:
            for line in fh.readlines()[1:]:
                f = line.split()
                if len(f) > 2 and f[0] == ip:
                    return "REACHABLE" if int(f[2], 16) & 0x2 else "INCOMPLETE"
    except (OSError, ValueError, IndexError):
        pass
    return None


def _tcp_open(host, port, timeout=1.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def probe_link():
    """Capa 1: enlace local.

    No se usa ping como senal principal a proposito: el gateway de esta red
    (192.168.2.1) DESCARTA ICMP echo, asi que un `ping` al gateway da 100% de
    perdida con internet funcionando perfecto. Basar la capa 1 en ping hacia
    declarar 'enlace caido' de forma permanente y cortaba toda la escalera.

    El orden va de la senal mas barata y confiable a la mas cara:
      1. ARP REACHABLE  -> el kernel confirmo alcance hace segundos. Gratis.
      2. TCP a un puerto del router -> atraviesa el filtro de ICMP.
      3. ping           -> ultimo recurso, y sirve para medir latencia.
    Solo si las tres fallan Y no hay entrada ARP se declara el enlace caido.
    """
    gw = default_gateway()
    if not gw:
        return Probe("enlace", FAIL, "No hay ruta por defecto (interfaz caida o sin DHCP).")

    state = neighbour_state(gw)
    if state == "REACHABLE":
        return Probe("enlace", OK, f"Gateway {gw} alcanzable (ARP REACHABLE).")

    for port in GATEWAY_TCP_PORTS:
        if _tcp_open(gw, port):
            return Probe("enlace", OK, f"Gateway {gw} responde en TCP/{port} (filtra ICMP).")

    ok, ms = _ping(gw, count=2, wait=1)
    if ok:
        return Probe("enlace", OK, f"Gateway {gw} responde ICMP.", ms)

    if state in ("STALE", "DELAY", "PROBE"):
        # Hay MAC conocida pero nada contesta: el switch/AP sigue ahi y el
        # router no. Es una falla, pero conviene decir que se vio.
        return Probe("enlace", FAIL, f"El gateway {gw} tiene entrada ARP {state} pero no responde en ningun puerto.")
    return Probe("enlace", FAIL, f"El gateway {gw} no responde y no hay entrada ARP: enlace fisico caido.")


def probe_wan():
    """Capa 2: salida a WAN por IP, sin DNS de por medio.

    Se prueban varias IPs y alcanza con una: declarar 'no hay internet' porque
    un unico anycast esta caido es exactamente el falso positivo que queremos
    sacarnos de encima.
    """
    reachable, latencies = [], []
    for ip in WAN_IPS:
        ok, ms = _ping(ip, count=2, wait=2)
        if ok:
            reachable.append(ip)
            if ms is not None:
                latencies.append(ms)
    if reachable:
        avg = sum(latencies) / len(latencies) if latencies else None
        return Probe("wan", OK, f"Responden {len(reachable)}/{len(WAN_IPS)} ({', '.join(reachable)}).", avg)
    return Probe("wan", FAIL, f"Ninguna IP externa responde ({', '.join(WAN_IPS)}).")


def _resolve_with(server, name, timeout=4):
    """Resuelve `name` contra un servidor puntual usando dig. (ok, detalle)."""
    if not shutil.which("dig"):
        return None, "dig no instalado"
    try:
        p = subprocess.run(
            ["dig", f"@{server}", "+short", "+time=2", "+tries=1", name, "A"],
            capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False, "timeout"
    answers = [l for l in (p.stdout or "").split() if l and l[0].isdigit()]
    if p.returncode == 0 and answers:
        return True, answers[0]
    return False, "sin respuesta"


def configured_resolvers():
    """Resolvers de /etc/resolv.conf. Puede ser el stub 127.0.0.53 de systemd."""
    out = []
    try:
        with open("/etc/resolv.conf") as fh:
            for line in fh:
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) > 1:
                        out.append(parts[1])
    except OSError:
        pass
    return out


def probe_dns():
    """Capa 3: resolucion.

    Se contrasta el resolver configurado contra uno externo. Sin ese contraste
    no se puede separar 'mi resolver esta roto' (arreglable: cambiar DNS) de
    'no hay DNS en ningun lado' (sintoma de que tampoco hay WAN). En esta red
    importa el doble porque el resolver configurado es el propio gateway.
    """
    # Primero la resolucion del sistema tal como la ve cualquier proceso.
    t0 = time.monotonic()
    try:
        socket.getaddrinfo(DNS_PROBE_NAME, 80, proto=socket.IPPROTO_TCP)
        system_ok = True
    except (socket.gaierror, OSError):
        system_ok = False
    ms = (time.monotonic() - t0) * 1000

    ext_ok, ext_detail = _resolve_with(DNS_EXTERNAL, DNS_PROBE_NAME)

    if system_ok:
        return Probe("dns", OK, f"{DNS_PROBE_NAME} resuelve por el sistema.", ms)

    resolvers = ", ".join(configured_resolvers()) or "desconocido"
    if ext_ok:
        # El resolver externo si contesta => hay ruta, lo roto es el local.
        return Probe("dns", FAIL, f"El resolver local ({resolvers}) no resuelve, pero {DNS_EXTERNAL} si. DNS local caido.")
    if ext_ok is None:
        return Probe("dns", FAIL, f"No resuelve {DNS_PROBE_NAME} (resolver: {resolvers}).")
    return Probe("dns", FAIL, f"No resuelve ni por {resolvers} ni por {DNS_EXTERNAL}. DNS caido en toda la ruta.")


def probe_http():
    """Capa 4: HTTP/TLS real.

    Un captive portal o un DPI dejan pasar ping y DNS pero secuestran el
    trafico web. La sonda espera un 204 vacio: si vuelve 200 con contenido,
    hay algo respondiendo por el destino real.
    """
    if not shutil.which("curl"):
        return Probe("http", SKIP, "curl no instalado.")
    t0 = time.monotonic()
    try:
        p = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "8", HTTP_PROBE_URL],
            capture_output=True, text=True, timeout=12,
        )
    except (subprocess.TimeoutExpired, OSError):
        return Probe("http", FAIL, f"Sin respuesta de {HTTP_PROBE_URL} (timeout).")
    ms = (time.monotonic() - t0) * 1000
    code = (p.stdout or "").strip()
    if code == str(HTTP_PROBE_EXPECT):
        return Probe("http", OK, f"HTTPS OK ({code}).", ms)
    if code in ("000", ""):
        return Probe("http", FAIL, "El handshake TLS no completa (bloqueo o MITM).")
    return Probe("http", FAIL, f"Se esperaba {HTTP_PROBE_EXPECT} y vino {code}: posible captive portal o proxy transparente.")


def probe_guardian():
    """Capa 5: estado del ONU segun el ISP Uplink Guardian.

    Es la unica capa que el pentium no puede medir solo: desde adentro no hay
    forma de distinguir 'el ONU esta muerto' de 'el ONU esta bien pero el ISP
    no entrega'. El Guardian si lo sabe, y ademas ya lleva el historial de
    cortes. Solo se lee -- el Centinela nunca dispara un reboot.
    """
    if not GUARDIAN_URL:
        return Probe("onu", SKIP, "ISP_GUARDIAN_URL no configurado."), None
    try:
        p = subprocess.run(
            ["curl", "-s", "--max-time", "6", f"{GUARDIAN_URL}/api/status"],
            capture_output=True, text=True, timeout=10,
        )
        data = json.loads(p.stdout)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return Probe("onu", SKIP, "El Guardian no responde."), None

    onu_up, wan_up = data.get("onu_up"), data.get("wan_up")
    if onu_up is False:
        return Probe("onu", FAIL, "El ONU no responde: modem colgado o sin energia."), data
    if wan_up is False:
        return Probe("onu", FAIL, "El ONU responde pero el Guardian no ve WAN: la falla es del ISP."), data
    return Probe("onu", OK, "ONU y WAN OK segun el Guardian."), data


# ==========================================
# DECISION (pura: se testea sin red)
# ==========================================

# Orden de la escalera. La primera capa que falla es la causa raiz; lo que
# venga despues es consecuencia y no aporta.
LAYER_ORDER = ["enlace", "wan", "dns", "http", "onu"]

_VERDICTS = {
    "enlace": ("🔌 Enlace local caido", "El problema esta adentro de casa: el gateway no responde. No es el ISP."),
    "wan":    ("🌐 Sin salida a WAN", "Hay red local pero no se alcanza ninguna IP externa."),
    "dns":    ("🧭 DNS caido", "Hay salida a internet, pero no se resuelven nombres."),
    "http":   ("🕵️ Trafico interceptado", "Ping y DNS funcionan, pero el trafico web no llega limpio."),
    "onu":    ("📡 Falla del ONU / ISP", "El enlace de fibra es el que esta caido."),
}


def diagnose(probes):
    """Devuelve el veredicto a partir de las sondas ya medidas.

    Pura a proposito: recibe la lista de Probe y no toca la red, asi que toda
    la logica de 'que capa es la culpable' se testea con datos armados a mano.
    """
    by_layer = {p.layer: p for p in probes}
    failed = [name for name in LAYER_ORDER if name in by_layer and by_layer[name].failed]

    if not failed:
        return {"healthy": True, "layer": None, "title": "🌐 Red OK",
                "summary": "Todas las capas responden.", "probes": probes}

    # La capa ONU manda sobre las de arriba: si la fibra esta caida, que no haya
    # WAN ni DNS es consecuencia, no un hallazgo aparte.
    root = "onu" if "onu" in failed else failed[0]
    title, summary = _VERDICTS[root]

    # Matiz util: WAN caido con ONU sano y alcanzable acota la culpa al ISP.
    if root == "wan" and by_layer.get("onu") and by_layer["onu"].ok:
        summary += " El ONU responde, asi que el corte es aguas arriba (ISP)."

    return {"healthy": False, "layer": root, "title": title,
            "summary": summary, "detail": by_layer[root].detail,
            "failed": failed, "probes": probes}


def run_all_probes():
    """Corre la escalera completa. Bloqueante: llamar con asyncio.to_thread."""
    probes = [probe_link()]
    # Sin enlace local no tiene sentido castigar 20s en sondas que van a fallar
    # todas por la misma razon.
    if probes[0].ok:
        probes.append(probe_wan())
        probes.append(probe_dns())
        if probes[-2].ok:
            probes.append(probe_http())
    guardian_probe, guardian_data = probe_guardian()
    probes.append(guardian_probe)
    return probes, guardian_data


# ==========================================
# SPEEDTEST
# ==========================================

# Servidor FIJO. La auto-seleccion de speedtest-cli elige por cercania
# geografica declarada, y en esta conexion devuelve servidores en Brasil a
# 3400 km. Si cada corrida usa un servidor distinto los numeros no son
# comparables entre si y cualquier umbral de "internet lento" da falsos
# positivos. Con el server fijo se mide siempre contra la misma referencia.
SPEEDTEST_SERVER_ID = os.getenv("SPEEDTEST_SERVER_ID", "").strip()
SPEEDTEST_TIMEOUT = int(os.getenv("SPEEDTEST_TIMEOUT", "120"))


def speedtest_available():
    return shutil.which("speedtest-cli") is not None


def run_speedtest():
    """Corre speedtest-cli y normaliza el JSON. Bloqueante (~25s) y consume
    ~40 MB de trafico: nunca llamarlo desde el event loop ni sin cooldown.

    Devuelve dict con down/up en Mbps, o {"error": ...}.
    """
    if not speedtest_available():
        return {"error": "speedtest-cli no esta instalado."}
    cmd = ["speedtest-cli", "--json", "--secure"]
    if SPEEDTEST_SERVER_ID:
        cmd += ["--server", SPEEDTEST_SERVER_ID]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=SPEEDTEST_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": f"speedtest no termino en {SPEEDTEST_TIMEOUT}s."}
    except OSError as e:
        return {"error": str(e)}
    if p.returncode != 0:
        return {"error": (p.stderr or "speedtest fallo").strip()[:200]}
    return parse_speedtest(p.stdout)


def parse_speedtest(raw):
    """Normaliza la salida JSON. Separado de run_speedtest para poder testear
    el parseo con una salida grabada, sin consumir ancho de banda."""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return {"error": "speedtest devolvio algo que no es JSON."}
    server = data.get("server") or {}
    try:
        return {
            "down_mbps": float(data.get("download", 0)) / 1_000_000,
            "up_mbps": float(data.get("upload", 0)) / 1_000_000,
            "ping_ms": float(data.get("ping", 0)),
            "server": f"{server.get('sponsor', '?')} ({server.get('name', '?')}, {server.get('country', '?')})",
            "server_id": str(server.get("id", "")),
            "distance_km": float(server.get("d", 0)),
            "isp": (data.get("client") or {}).get("isp", "?"),
        }
    except (TypeError, ValueError):
        return {"error": "speedtest devolvio campos incompletos."}


# Umbrales como fraccion de la mediana historica.
#
# Medido en esta conexion contra el MISMO servidor (67942), tres corridas
# espaciadas 40s: 15.2 / 18.6 / 19.2 Mbps -- 26% de dispersion en dos minutos.
# Y la misma conexion contra el mismo servidor media 24.9 Mbps media hora
# antes. O sea: el ruido normal de este enlace es enorme, y un umbral apretado
# convierte esa varianza en alertas falsas.
#
# Por eso "degraded" (que solo colorea el embed) esta en 0.6 y no en 0.75, y
# "slow" (lo unico que dispara alerta) en 0.45: para gatillar hace falta una
# caida mayor que cualquier oscilacion observada.
SPEED_SLOW_RATIO = float(os.getenv("SPEEDTEST_SLOW_RATIO", "0.45"))
SPEED_DEGRADED_RATIO = float(os.getenv("SPEEDTEST_DEGRADED_RATIO", "0.6"))
SPEED_MIN_SAMPLES = int(os.getenv("SPEEDTEST_MIN_SAMPLES", "5"))


def evaluate_speed(result, history):
    """Compara contra la mediana historica en vez de un umbral absoluto.

    Un umbral fijo no sirve: el numero depende del servidor, de la hora y del
    tramo internacional. Lo que importa es la desviacion respecto de lo normal
    en ESTA conexion. Con pocas muestras no se opina: se esta aprendiendo.

    Se usa mediana y no promedio a proposito: una corrida fallida a 0.5 Mbps
    arrastraria el promedio hacia abajo y despues lo lento pareceria normal.
    """
    if result.get("error") or not history:
        return None
    samples = sorted(h for h in history if h > 0)
    if len(samples) < SPEED_MIN_SAMPLES:
        return {"verdict": "baseline",
                "msg": f"Juntando linea base ({len(samples)}/{SPEED_MIN_SAMPLES} muestras)."}
    mid = len(samples) // 2
    median = samples[mid] if len(samples) % 2 else (samples[mid - 1] + samples[mid]) / 2
    if median <= 0:
        return None
    ratio = result["down_mbps"] / median
    pct = (1 - ratio) * 100
    if ratio < SPEED_SLOW_RATIO:
        return {"verdict": "slow", "median": median, "pct": pct,
                "msg": f"**{pct:.0f}% por debajo** de tu mediana ({median:.1f} Mbps)."}
    if ratio < SPEED_DEGRADED_RATIO:
        return {"verdict": "degraded", "median": median, "pct": pct,
                "msg": f"{pct:.0f}% por debajo de tu mediana ({median:.1f} Mbps)."}
    return {"verdict": "ok", "median": median, "pct": pct,
            "msg": f"Normal para esta conexion (mediana {median:.1f} Mbps)."}
