"""Que cuenta como un login SSH normal en esta flota, y que no.

El correlador de `security_events.py` vive 900 segundos en memoria: alcanza
para atar un fail2ban a los fallos que lo causaron, pero no para responder
"esta clave, ¿entro alguna vez antes?". Esa pregunta necesita memoria que
sobreviva a los reinicios del bot, y es la unica forma de que un login raro se
distinga de la rutina.

El criterio es deliberadamente conservador: se avisa por lo que NO se puede
explicar, no por lo que se ve poco. Una alerta que salta cada noche cuando
Dokploy hace su deploy programado termina silenciada, y entonces tampoco avisa
el dia que el login lo hace otro.

Las senales, de mas a menos fuerte:

* **Clave desconocida.** sshd acepto un fingerprint que no figura en ningun
  `authorized_keys` legible. O alguien agrego una clave sin avisar, o el
  `authorized_keys` fue modificado despues del login. Es la unica senal que
  por si sola justifica despertar a alguien.
* **Password donde deberia haber clave.** Un host keys-only que acepta una
  password es una violacion de politica, aunque el que entro sea el dueno.
* **Clave conocida, usuario nuevo.** La clave de un deploy que siempre entro
  como `dokploy` ahora entra como `root`.
* **Origen nuevo.** La subred nunca se habia visto para ese par (clave,
  usuario). Una clave de automatizacion tiene un origen fijo; una clave
  interactiva no, y por eso la senal se pondera con cuantas subredes distintas
  ya tiene el perfil.
* **Horario atipico.** Solo para claves con agenda: si el perfil viene
  entrando siempre en la misma franja, salirse de ella significa algo. Para
  una clave interactiva, que entra a cualquier hora, la senal no se emite.
"""

from datetime import datetime, timezone
import ipaddress
import json
import os
import tempfile

INFO = "info"
WARNING = "warning"
CRITICAL = "critica"

_SEVERITY_ORDER = {INFO: 0, WARNING: 1, CRITICAL: 2}

# Un perfil necesita historia antes de que "nunca vi esto" signifique algo.
# Con dos logins previos, el tercero desde otra subred no es una anomalia: es
# que todavia no sabemos como se comporta esa clave.
MIN_OBSERVATIONS = 5
# Cuantas franjas horarias distintas admite un perfil antes de considerarse sin
# agenda. Dokploy entra siempre 20:50 (1 franja); una persona no.
SCHEDULED_HOUR_SPAN = 6
# A partir de cuantas subredes distintas se asume que la clave es movil y deja
# de avisarse por origen nuevo.
ROAMING_SUBNETS = 4
RETENTION_DAYS = 180


def _now(value=None):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def source_group(ip):
    """Agrupa una IP de origen en algo comparable entre logins.

    No se guarda la IP exacta a proposito: un cliente DHCP cambia de IP dentro
    de la misma LAN y no por eso es otro. Para IPv4 el /24 es el grupo natural
    en esta red; para IPv6, el /64.
    """
    text = str(ip or "").strip()
    if not text:
        return ""
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text[:64]
    if address.is_loopback:
        return "loopback"
    network = ipaddress.ip_network(
        f"{address}/{24 if address.version == 4 else 64}", strict=False
    )
    return str(network)


# Rangos explicitos en vez de `ipaddress.is_private`: esa propiedad tambien
# devuelve True para los bloques de documentacion de la RFC 5737 (192.0.2.0/24,
# 198.51.100.0/24, 203.0.113.0/24), que no son direcciones de la red de nadie.
# Tratarlas como internas ablandaria la severidad de un origen externo.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)


def is_private(ip):
    """True solo para direcciones que pueden pertenecer a una red propia."""
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    return any(address in network for network in _INTERNAL_NETWORKS)


class Assessment:
    """Veredicto sobre un login, listo para decidir si se publica."""

    def __init__(self):
        self.reasons = []
        self.severity = None

    def add(self, severity, text):
        self.reasons.append({"severity": severity, "text": text})
        if (
            self.severity is None
            or _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[self.severity]
        ):
            self.severity = severity
        return self

    @property
    def suspicious(self):
        """INFO no es sospecha: es contexto que se muestra sin encabezar nada."""
        return self.severity in (WARNING, CRITICAL)

    @property
    def texts(self):
        return [reason["text"] for reason in self.reasons]

    def __bool__(self):
        return bool(self.reasons)


class LoginBaseline:
    """Perfiles persistentes por (nodo, fingerprint, usuario)."""

    def __init__(self, path="", min_observations=MIN_OBSERVATIONS):
        self.path = str(path or "")
        self.min_observations = min_observations
        self.profiles = {}
        self.loaded = False

    # -- persistencia ----------------------------------------------------
    def load(self):
        self.loaded = True
        if not self.path or not os.path.exists(self.path):
            return self
        try:
            with open(self.path, encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError):
            # Un archivo corrupto no puede tumbar el bot ni, peor, hacerlo
            # arrancar en un estado donde todo login parece nuevo y alerta.
            return self
        profiles = payload.get("profiles") if isinstance(payload, dict) else None
        if isinstance(profiles, dict):
            self.profiles = {
                key: value
                for key, value in profiles.items()
                if isinstance(value, dict)
            }
        return self

    def save(self):
        if not self.path:
            return False
        directory = os.path.dirname(self.path) or "."
        try:
            os.makedirs(directory, mode=0o700, exist_ok=True)
            handle = tempfile.NamedTemporaryFile(
                "w", encoding="utf-8", dir=directory, delete=False
            )
            try:
                json.dump(
                    {"version": 1, "profiles": self.profiles},
                    handle,
                    separators=(",", ":"),
                )
            finally:
                handle.close()
            os.replace(handle.name, self.path)
            os.chmod(self.path, 0o600)
        except OSError:
            return False
        return True

    def prune(self, now=None, retention_days=RETENTION_DAYS):
        cutoff = _now(now).timestamp() - retention_days * 86_400
        stale = [
            key
            for key, profile in self.profiles.items()
            if float(profile.get("last_seen") or 0) < cutoff
        ]
        for key in stale:
            self.profiles.pop(key, None)
        return len(stale)

    # -- modelo ----------------------------------------------------------
    @staticmethod
    def key_for(node, fingerprint, user):
        # Sin fingerprint el perfil se ancla al metodo de autenticacion, para
        # que los logins por password no se mezclen con los de clave.
        return "|".join([
            str(node or "?"),
            str(fingerprint or "sin-clave"),
            str(user or "?"),
        ])

    def profile(self, node, fingerprint, user):
        return self.profiles.get(self.key_for(node, fingerprint, user))

    def observe(self, node, login, now=None):
        """Incorpora un login al perfil. Siempre se llama, alerte o no.

        Aprender tambien de los logins sospechosos es intencional: si de verdad
        hubo una intrusion, la segunda conexion no deberia alertar igual que la
        primera y enterrar el resto del canal. La primera queda registrada.
        """
        moment = _now(now)
        key = self.key_for(node, login.get("fingerprint"), login.get("user"))
        profile = self.profiles.setdefault(key, {
            "first_seen": moment.timestamp(),
            "last_seen": 0.0,
            "count": 0,
            "sources": {},
            "hours": {},
            "methods": {},
        })
        profile["last_seen"] = moment.timestamp()
        profile["count"] = int(profile.get("count") or 0) + 1
        group = source_group(login.get("ip"))
        if group:
            sources = profile.setdefault("sources", {})
            sources[group] = int(sources.get(group) or 0) + 1
        hours = profile.setdefault("hours", {})
        hour = str(moment.astimezone().hour)
        hours[hour] = int(hours.get(hour) or 0) + 1
        method = str(login.get("method") or "?")
        methods = profile.setdefault("methods", {})
        methods[method] = int(methods.get(method) or 0) + 1
        return profile

    def assess(self, node, login, directory=None, now=None):
        """Devuelve el veredicto SIN modificar el perfil.

        Separar `assess` de `observe` es lo que permite comparar el login
        contra el pasado y recien despues incorporarlo; hacerlo junto haria que
        todo login sea, por construccion, conocido.
        """
        moment = _now(now)
        verdict = Assessment()
        fingerprint = str(login.get("fingerprint") or "")
        user = str(login.get("user") or "")
        method = str(login.get("method") or "")
        ip = login.get("ip")

        if method == "password":
            verdict.add(
                CRITICAL,
                "Autenticacion por **password**, no por clave publica.",
            )
        elif method == "publickey" and not fingerprint:
            verdict.add(
                INFO,
                "sshd no registro el fingerprint de la clave.",
            )

        if fingerprint and directory is not None and directory.loaded:
            if directory.is_authorized(fingerprint):
                allowed = directory.authorized_users(fingerprint)
                if allowed and user and user not in allowed:
                    verdict.add(
                        CRITICAL,
                        f"La clave esta autorizada para "
                        f"{', '.join(sorted(allowed))}, pero entro como "
                        f"`{user}`.",
                    )
            elif directory.covers(user):
                verdict.add(
                    CRITICAL,
                    "El fingerprint no figura en ningun `authorized_keys` "
                    "del nodo.",
                )
            else:
                verdict.add(
                    INFO,
                    f"No se pudo leer el `authorized_keys` de `{user}`: la "
                    "clave no es verificable.",
                )

        profile = self.profile(node, fingerprint, user)
        if profile is None:
            other_users = [
                stored_user
                for (stored_node, stored_fp, stored_user) in self._index()
                if stored_node == node
                and stored_fp == fingerprint
                and fingerprint
                and stored_user != user
            ]
            if other_users:
                verdict.add(
                    WARNING,
                    "Esta clave nunca habia entrado como "
                    f"`{user}` (si como {', '.join(sorted(set(other_users)))}).",
                )
            else:
                verdict.add(
                    WARNING if fingerprint else INFO,
                    "Primer login registrado para esta combinacion de clave y "
                    "usuario.",
                )
            return verdict

        observations = int(profile.get("count") or 0)
        if observations < self.min_observations:
            # Perfil todavia en formacion: no hay base para llamar raro a nada.
            return verdict

        sources = profile.get("sources") or {}
        group = source_group(ip)
        if group and group not in sources and len(sources) < ROAMING_SUBNETS:
            detail = (
                "IP externa nueva" if not is_private(ip) else "subred nueva"
            )
            verdict.add(
                CRITICAL if not is_private(ip) else WARNING,
                f"{detail} (`{group}`); hasta ahora solo "
                f"{', '.join(sorted(sources))}.",
            )

        hours = {
            int(hour): count
            for hour, count in (profile.get("hours") or {}).items()
            if str(hour).isdigit()
        }
        current_hour = moment.astimezone().hour
        if (
            hours
            and len(hours) <= SCHEDULED_HOUR_SPAN
            and current_hour not in hours
        ):
            observed = ", ".join(f"{hour:02d}h" for hour in sorted(hours))
            verdict.add(
                WARNING,
                f"Horario fuera de la agenda habitual de esta clave "
                f"({observed}).",
            )

        methods = profile.get("methods") or {}
        if method and methods and method not in methods:
            verdict.add(
                WARNING,
                f"Metodo de autenticacion nuevo para esta clave: `{method}`.",
            )
        return verdict

    def _index(self):
        for key in self.profiles:
            parts = key.split("|")
            if len(parts) == 3:
                yield parts[0], parts[1], parts[2]
