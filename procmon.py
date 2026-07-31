"""Muestreo de procesos de alto consumo.

Existe porque el diagnostico de procesos estaba roto de una forma silenciosa.

`psutil.Process.cpu_percent()` sin intervalo devuelve el uso ACUMULADO DESDE LA
LLAMADA ANTERIOR sobre ese mismo objeto Process. La primera llamada siempre
devuelve 0.0. El codigo viejo hacia:

    for proc in psutil.process_iter(['pid','name','cpu_percent',...]):

...y ordenaba por ese campo. En `!top` funcionaba de casualidad, porque el
comando hacia una pasada de cebado y dormia 1s antes de medir. Pero
`watch_resources` -- la alerta de CPU CRITICA, o sea el unico momento en que
importa saber quien se come el CPU -- lo llamaba en frio: todos los procesos
devolvian 0.0, el sort no ordenaba nada y quedaban en orden de PID. La alerta
que llega al celular a las 3 AM listaba systemd, kthreadd y kworker con 0%.

La solucion no es copiar el sleep(1) a la alerta: bloquear el event loop de
discord.py un segundo cada vez que hay que alertar es peor. Lo que se hace es
mantener vivos los objetos Process entre muestreos y refrescarlos desde el loop
que ya corre cada minuto; asi cada lectura es el promedio real del ultimo
minuto y las alertas leen datos calientes sin dormir ni bloquear.
"""
import time

import psutil

CPU_COUNT = psutil.cpu_count() or 1


class ProcessSampler:
    """Mantiene los objetos Process vivos para que cpu_percent() mida de verdad.

    Guardar los Process entre llamadas es el punto entero de la clase: si se
    reconstruyen en cada muestreo, cada cpu_percent() vuelve a ser la primera
    llamada de ese objeto y devuelve 0.0 para siempre.
    """

    def __init__(self):
        self._procs = {}
        self.last_sample = []
        self.last_ts = None

    def _iter_procs(self):
        """Procesos vivos, reutilizando los objetos ya conocidos."""
        seen = set()
        for proc in psutil.process_iter(["pid"]):
            pid = proc.info["pid"]
            seen.add(pid)
            if pid not in self._procs:
                self._procs[pid] = proc
            yield self._procs[pid]
        # Los procesos muertos se sacan del cache; si no, el dict crece sin
        # techo en un host que levanta muchos procesos cortos.
        for pid in set(self._procs) - seen:
            self._procs.pop(pid, None)

    def refresh(self):
        """Relee las tasas. La ventana es el tiempo desde el refresh anterior.

        Llamado desde el loop de un minuto, cada lectura es el promedio del
        ultimo minuto: justo la ventana que quieren las alertas sostenidas.
        """
        sample = []
        for proc in self._iter_procs():
            try:
                cpu = proc.cpu_percent(None)
                with proc.oneshot():
                    name = proc.name()
                    mem = proc.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                continue
            sample.append({
                "pid": proc.pid,
                "name": name,
                # cpu_percent de psutil es POR NUCLEO: llega a 100*ncores (200%
                # en el E5400). Se normaliza para que sea comparable con el CPU%
                # del sistema que el bot muestra al lado; sin esto un proceso
                # aparecia con 180% junto a un sistema al 90% y no cerraba.
                "cpu": cpu / CPU_COUNT,
                "cpu_raw": cpu,
                "mem": mem or 0.0,
            })
        self.last_sample = sample
        self.last_ts = time.monotonic()
        return sample

    def warm(self):
        """True si ya hubo al menos un refresh con datos utiles.

        El primer refresh despues de arrancar devuelve 0.0 en todo (es la
        primera llamada de cada objeto). Sirve para no publicar una tabla de
        ceros y hacerla pasar por medicion.
        """
        return bool(self.last_sample) and any(p["cpu"] > 0 for p in self.last_sample)

    def top(self, n=8, sort_by="cpu"):
        """Top-N de la ultima muestra. No hace I/O: las alertas lo llaman gratis."""
        key = "cpu" if sort_by == "cpu" else "mem"
        # `or 0.0` porque memory_percent() puede devolver None en procesos que
        # se vuelven inaccesibles entre el iter y la lectura: comparar None con
        # float revienta el sort con TypeError y se lleva puesta la alerta
        # entera. El codigo viejo tenia justo ese agujero.
        return sorted(self.last_sample, key=lambda p: p.get(key) or 0.0, reverse=True)[:n]

    def sample_now(self, interval=1.0):
        """Muestra puntual con ventana corta, para `!top` bajo demanda.

        Bloquea `interval` segundos: llamar siempre con asyncio.to_thread.
        """
        self.refresh()
        time.sleep(interval)
        return self.refresh()


sampler = ProcessSampler()


def format_top(procs, key="cpu", width=18):
    """Filas listas para un embed. Sin datos devuelve None, no una tabla vacia."""
    if not procs:
        return None
    return "\n".join(
        f"`{p['name'][:width]:<{width}}` {p[key]:>5.1f}% `{'█' * min(int(p[key] / 10), 10)}`"
        for p in procs
    )
