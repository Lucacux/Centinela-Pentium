"""Capa Docker del Centinela, consciente de Swarm.

Vive fuera de main.py por dos razones: main.py llama a bot.run() a nivel de
modulo (no se puede importar en un test) y esta logica es justo la que puede
fallar en silencio — un servicio mal agrupado se ve como un contenedor caido.
"""
import re
import shutil
import subprocess

# Bajo Swarm los contenedores se llaman "<servicio>.<slot>.<taskid>" y el taskid
# se regenera en CADA deploy. Mostrarlo es ruido y tipearlo es imposible, asi que
# toda esta capa habla de SERVICIOS: el nombre real de la task solo se usa
# internamente para pedirle logs o stats a Docker.
TASK_SUFFIX = re.compile(r'\.\d+\.[a-z0-9]{16,}$')


def service_of(container):
    """discordbots-mediabot.1.s4aflfw1qys6... -> discordbots-mediabot"""
    return TASK_SUFFIX.sub('', container)


def docker_cmd(args, timeout=30):
    """Corre docker SIN shell.

    Los nombres llegan desde Discord: interpolarlos en una string de shell
    (lo que se hacia antes) es ejecucion remota de comandos servida en bandeja.
    Con lista de argumentos no hay shell que parsear.
    """
    if not shutil.which("docker"):
        return False, "Docker no instalado."
    try:
        p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
        out = (p.stdout or "").strip() or (p.stderr or "").strip()
        return p.returncode == 0, out
    except subprocess.TimeoutExpired:
        return False, f"`docker {args[0]}` no respondio en {timeout}s."
    except Exception as e:
        return False, str(e)


def get_docker_stats():
    """CPU/RAM por task. Las claves son nombres de task, no de servicio."""
    ok, raw = docker_cmd(
        ["stats", "--no-stream", "--format", "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}"]
    )
    if not ok:
        return []
    containers = []
    for line in raw.splitlines():
        parts = line.split('|')
        if len(parts) < 4:
            continue
        try:
            containers.append({
                "name": parts[0].strip(),
                "service": service_of(parts[0].strip()),
                "cpu": float(parts[1].strip().rstrip('%')),
                "mem_usage": parts[2].strip(),
                "mem_pct": float(parts[3].strip().rstrip('%'))
            })
        except ValueError:
            continue
    return containers


def list_tasks():
    """Contenedores crudos, en el orden de docker ps (mas nuevo primero)."""
    ok, raw = docker_cmd(["ps", "-a", "--format", "{{.Names}}|{{.Status}}|{{.Image}}|{{.Ports}}"])
    if not ok or not raw.strip():
        return []
    tasks_out = []
    for line in raw.splitlines():
        parts = line.split('|')
        if len(parts) < 3:
            continue
        name = parts[0].strip()
        tasks_out.append({
            "name": name,
            "service": service_of(name),
            "status": parts[1].strip(),
            "image": parts[2].strip(),
            "ports": parts[3].strip() if len(parts) > 3 else "",
            "running": parts[1].strip().startswith("Up"),
        })
    return tasks_out


def group_services(tasks_in):
    """Colapsa las tasks en un item por servicio.

    Un redeploy de Swarm deja la task vieja en 'Exited' al lado de la nueva. Sin
    esto, un servicio sano se ve como un contenedor verde + uno rojo y el rojo
    parece una falla cuando en realidad es basura de deploy.
    """
    grouped = {}
    for t in tasks_in:
        svc = grouped.get(t["service"])
        if svc is None:
            grouped[t["service"]] = {"service": t["service"], "stale": 0, "current": t}
            continue
        # Gana la task corriendo; si no hay ninguna, la primera (= la mas nueva).
        if t["running"] and not svc["current"]["running"]:
            svc["current"] = t
        svc["stale"] += 1
    return list(grouped.values())


def resolve_service(name):
    """Matchea lo que escribio el usuario contra los servicios que existen.

    Devuelve (servicio, task_actual) o (None, None). Esto es la allowlist real:
    solo pasa lo que Docker ya reporta, y ALLOWED_RESTART filtra encima.
    """
    services = group_services(list_tasks())
    wanted = name.strip().lower()
    for s in services:
        if s["service"].lower() == wanted or s["current"]["name"].lower() == wanted:
            return s, s["current"]
    for s in services:
        if wanted in s["service"].lower():
            return s, s["current"]
    return None, None


def restart_service(name, task):
    """Reinicia de la forma correcta segun como este desplegado el servicio.

    Bajo Swarm `docker restart <task>` es la operacion equivocada: el
    orquestador ve morir la task y la recrea por su cuenta, asi que el reinicio
    ocurre por afuera del scheduler y no respeta update_config ni healthcheck.
    La operacion real es `service update --force`. Si no es un servicio de
    Swarm (o este nodo no es manager) `service inspect` falla y caemos al
    restart comun, que ahi si es lo correcto.
    """
    is_swarm, _ = docker_cmd(["service", "inspect", name, "--format", "{{.ID}}"], timeout=15)
    if is_swarm:
        return docker_cmd(["service", "update", "--force", name], timeout=180)
    return docker_cmd(["restart", task["name"]], timeout=60)

