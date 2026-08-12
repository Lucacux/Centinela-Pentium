"""Blindaje de los tasks.loop contra errores transitorios de Discord.

Un `tasks.loop` de discord.py que deja escapar una excepcion **se detiene para
siempre**: discord.py cancela la tarea y no la vuelve a lanzar. Un 503 pasajero
de la API de Discord --que no depende de nosotros y va a volver a pasar-- puede
dejar el monitoreo mudo por tiempo indefinido, y la unica senal seria la
ausencia de alertas, que es justo lo que no se nota.

Este modulo arma un manejador de error para cada loop: registra el fallo, espera
un backoff exponencial y vuelve a arrancarlo. El backoff evita machacar la API
cuando Discord esta caido de verdad; el reinicio evita que un corte de un minuto
apague el monitoreo hasta el proximo deploy.
"""

import asyncio
import traceback

# El primer reintento espera poco: la mayoria de los 5xx de Discord duran
# segundos. Los siguientes se espacian hasta MAX_DELAY.
BASE_DELAY = 30.0
MAX_DELAY = 900.0

# Si el loop aguanto mas que esto desde el ultimo fallo, la racha se considera
# terminada y el backoff vuelve a empezar de cero. Sin esto, un loop que falla
# una vez por semana terminaria arrastrando el delay maximo para siempre.
RESET_AFTER = 1800.0

# Cuanto esperamos a que discord.py termine de bajar la tarea antes de
# reiniciarla. start() sobre un loop todavia vivo lanza RuntimeError.
STOP_TIMEOUT = 30.0


def is_transient(exc):
    """True si el error parece de la red o de la API, no un bug nuestro.

    Se usa solo para redactar el aviso: los dos casos se reintentan igual,
    porque un loop detenido es peor que un loop que falla ruidosamente.
    """
    if isinstance(exc, (asyncio.TimeoutError, ConnectionError, OSError)):
        return True

    # No importamos discord ni aiohttp para no atar el modulo (ni sus tests) a
    # las librerias: nos alcanza con el nombre de la clase y el codigo HTTP.
    # Miramos toda la jerarquia, no solo la clase concreta, porque las
    # excepciones de discord.py son subclases (DiscordServerError, Forbidden y
    # NotFound heredan de HTTPException) y el nombre exacto se nos escaparia.
    ancestros = {klass.__name__ for klass in type(exc).__mro__}

    if ancestros & {"GatewayNotFound", "ClientConnectorError",
                    "ServerDisconnectedError", "ClientOSError", "ClientError"}:
        return True

    # DiscordServerError ya es 5xx por definicion; para el resto de la familia
    # HTTPException decide el codigo, que es lo que distingue un 503 pasajero
    # de un 403 que va a fallar igual dentro de una hora.
    if "DiscordServerError" in ancestros:
        return True
    if "HTTPException" in ancestros:
        status = getattr(exc, "status", None)
        return status is not None and (status == 429 or 500 <= status < 600)
    return False


def next_delay(failures, base=BASE_DELAY, maximum=MAX_DELAY):
    """Backoff exponencial con techo. `failures` arranca en 1."""
    if failures < 1:
        failures = 1
    return min(base * (2 ** (failures - 1)), maximum)


class LoopGuard:
    """Reinicia los loops que se caen, con backoff y aviso.

    Las dependencias entran por parametro (`sleep`, `now`, `log`, `notify`)
    para poder probar el comportamiento sin dormir de verdad ni hablar con
    Discord.
    """

    def __init__(self, *, base_delay=BASE_DELAY, max_delay=MAX_DELAY,
                 reset_after=RESET_AFTER, sleep=None, now=None, log=print,
                 notify=None):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.reset_after = reset_after
        self._sleep = sleep or asyncio.sleep
        self._now = now or (lambda: asyncio.get_event_loop().time())
        self._log = log
        self._notify = notify
        # nombre -> {"failures": int, "last": float}
        self.state = {}

    def _record(self, name):
        """Suma un fallo a la racha del loop y devuelve cuantos van."""
        entry = self.state.get(name)
        moment = self._now()
        if entry is None or (moment - entry["last"]) > self.reset_after:
            entry = {"failures": 0, "last": moment}
        entry["failures"] += 1
        entry["last"] = moment
        self.state[name] = entry
        return entry["failures"]

    async def _announce(self, text):
        """Avisar nunca puede tumbar al guardia: si Discord esta caido, este
        mismo aviso es lo que va a fallar."""
        if self._notify is None:
            return
        try:
            await self._notify(text)
        except Exception as exc:  # noqa: BLE001 - best effort a proposito
            self._log(f"[loop_guard] no se pudo avisar por Discord: {exc!r}")

    async def handle(self, loop, name, exc):
        """Manejar la caida de un loop: registrar, esperar y relanzar."""
        failures = self._record(name)
        delay = next_delay(failures, self.base_delay, self.max_delay)
        clase = "transitorio" if is_transient(exc) else "no esperado"

        self._log(
            f"[loop_guard] '{name}' se cayo ({clase}, fallo #{failures}): "
            f"{type(exc).__name__}: {exc}"
        )
        self._log("".join(traceback.format_exception(
            type(exc), exc, exc.__traceback__)))

        # Solo avisamos el primero de cada racha: si Discord esta caido, los
        # 15 loops se caen juntos y no queremos 15 mensajes por reintento.
        if failures == 1:
            await self._announce(
                f"⚠️ El monitoreo `{name}` se cayo por un error {clase} "
                f"(`{type(exc).__name__}`). Reintento en {int(delay)}s."
            )

        await self._sleep(delay)

        if not await self._wait_stopped(loop):
            self._log(
                f"[loop_guard] '{name}' sigue figurando activo despues de "
                f"{STOP_TIMEOUT}s; no lo relanzo para no duplicarlo."
            )
            return False

        try:
            loop.start()
        except Exception as exc2:  # noqa: BLE001 - el guardia no puede morir
            self._log(f"[loop_guard] no se pudo relanzar '{name}': {exc2!r}")
            return False

        self._log(f"[loop_guard] '{name}' relanzado tras {int(delay)}s.")
        if failures == 1:
            await self._announce(f"✅ El monitoreo `{name}` volvio a arrancar.")
        return True

    async def _wait_stopped(self, loop):
        """Esperar a que discord.py de por terminada la tarea vieja."""
        waited = 0.0
        step = 1.0
        while loop.is_running() and waited < STOP_TIMEOUT:
            await self._sleep(step)
            waited += step
        return not loop.is_running()


def arm(loop, guard, name=None):
    """Registrar el manejador de error de `loop` en `guard`.

    Devuelve el nombre usado, que es el de la corrutina salvo que se pida otro.
    """
    if name is None:
        name = getattr(loop, "coro", None)
        name = getattr(name, "__name__", None) or repr(loop)

    async def on_loop_error(exc):
        await guard.handle(loop, name, exc)

    loop.error(on_loop_error)
    return name


def arm_all(loops, guard):
    """Armar varios loops de una. Devuelve los nombres armados."""
    return [arm(loop, guard) for loop in loops]
