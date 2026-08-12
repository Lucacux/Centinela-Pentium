import asyncio

import pytest

import loop_guard
from loop_guard import LoopGuard, arm, arm_all, is_transient, next_delay


class HTTPException(Exception):
    """Imita discord.HTTPException sin depender de discord.

    El nombre importa: loop_guard clasifica por la jerarquia de clases para no
    tener que importar discord.
    """

    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status = status


class DiscordServerError(HTTPException):
    """El 503 real que dejo mudo al watch_remote_arch el 2026-08-03.

    Igual que en discord.py, hereda de HTTPException.
    """

    def __init__(self, status=503):
        super().__init__(status)


class FakeLoop:
    """Un tasks.loop de mentira: registra el handler y cuenta los start()."""

    def __init__(self, name="fake_loop", running=False, start_error=None,
                 stops_after=0):
        self.coro = type("C", (), {"__name__": name})()
        self._running = running
        self.starts = 0
        self.handler = None
        self.start_error = start_error
        # Cuantas consultas a is_running() faltan para que se de por detenido.
        self._stops_after = stops_after

    def error(self, coro):
        self.handler = coro
        return coro

    def is_running(self):
        if self._stops_after > 0:
            self._stops_after -= 1
            return True
        return self._running

    def start(self):
        if self.start_error:
            raise self.start_error
        self.starts += 1
        self._running = True

    def crash(self):
        """Lo que hace discord.py al dejar escapar una excepcion: baja la tarea."""
        self._running = False


class Clock:
    """Reloj y sleep falsos: el tiempo avanza solo cuando alguien duerme."""

    def __init__(self):
        self.now = 1000.0
        self.slept = []

    async def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds

    def time(self):
        return self.now


def build(**kwargs):
    clock = Clock()
    logs = []
    sent = []

    async def notify(text):
        sent.append(text)

    guard = LoopGuard(
        sleep=clock.sleep,
        now=clock.time,
        log=logs.append,
        notify=kwargs.pop("notify", notify),
        **kwargs,
    )
    return guard, clock, logs, sent


def caida(guard, loop, name, exc=None):
    """Simular un ciclo completo: el loop se cae y el guardia lo atiende."""
    loop.crash()
    return asyncio.run(guard.handle(loop, name, exc or DiscordServerError()))


# --------------------------------------------------------------------------
# is_transient
# --------------------------------------------------------------------------
@pytest.mark.parametrize("exc", [
    DiscordServerError("503 Service Unavailable"),
    HTTPException(503),
    HTTPException(500),
    HTTPException(429),
    asyncio.TimeoutError(),
    ConnectionResetError(),
    OSError("network unreachable"),
])
def test_errores_de_red_y_api_son_transitorios(exc):
    assert is_transient(exc) is True


@pytest.mark.parametrize("exc", [
    HTTPException(403),
    HTTPException(404),
    KeyError("falta la clave"),
    ValueError("bug nuestro"),
])
def test_los_errores_nuestros_no_son_transitorios(exc):
    assert is_transient(exc) is False


def test_httpexception_sin_status_no_se_asume_transitoria():
    exc = HTTPException(500)
    del exc.status
    assert is_transient(exc) is False


# --------------------------------------------------------------------------
# next_delay
# --------------------------------------------------------------------------
def test_el_backoff_crece_y_tiene_techo():
    assert next_delay(1, base=30, maximum=900) == 30
    assert next_delay(2, base=30, maximum=900) == 60
    assert next_delay(3, base=30, maximum=900) == 120
    assert next_delay(99, base=30, maximum=900) == 900


def test_el_backoff_tolera_un_contador_invalido():
    assert next_delay(0, base=30, maximum=900) == 30


# --------------------------------------------------------------------------
# El comportamiento que importa: el loop vuelve
# --------------------------------------------------------------------------
def test_un_503_relanza_el_loop():
    guard, clock, _, _ = build()
    loop = FakeLoop("watch_remote_arch")

    ok = asyncio.run(guard.handle(loop, "watch_remote_arch",
                                  DiscordServerError("503")))

    assert ok is True
    assert loop.starts == 1, "el loop tiene que volver a arrancar"
    assert clock.slept == [30.0], "y esperar el backoff antes de hacerlo"


def test_un_error_no_transitorio_tambien_relanza():
    """Un bug nuestro no puede dejar el monitoreo mudo hasta el proximo deploy."""
    guard, _, _, _ = build()
    loop = FakeLoop("watch_network")

    ok = asyncio.run(guard.handle(loop, "watch_network", ValueError("bug")))

    assert ok is True
    assert loop.starts == 1


def test_los_fallos_seguidos_espacian_el_reintento():
    guard, clock, _, _ = build()
    loop = FakeLoop("watch_services")

    for _ in range(4):
        caida(guard, loop, "watch_services")

    assert clock.slept == [30.0, 60.0, 120.0, 240.0]
    assert loop.starts == 4


def test_el_backoff_respeta_el_techo():
    guard, clock, _, _ = build(base_delay=30.0, max_delay=100.0)
    loop = FakeLoop()

    for _ in range(5):
        caida(guard, loop, "x")

    assert clock.slept == [30.0, 60.0, 100.0, 100.0, 100.0]


def test_una_racha_vieja_no_arrastra_el_backoff():
    """Un fallo por semana no puede terminar esperando 15 minutos."""
    guard, clock, _, _ = build(reset_after=1800.0)
    loop = FakeLoop()

    caida(guard, loop, "x")
    clock.now += 5000  # pasa mucho tiempo sano
    caida(guard, loop, "x")

    assert clock.slept == [30.0, 30.0], "el segundo fallo arranca de cero"


def test_cada_loop_lleva_su_propia_racha():
    guard, clock, _, _ = build()
    a, b = FakeLoop("a"), FakeLoop("b")

    caida(guard, a, "a")
    caida(guard, a, "a")
    caida(guard, b, "b")

    assert clock.slept == [30.0, 60.0, 30.0]


# --------------------------------------------------------------------------
# Avisos
# --------------------------------------------------------------------------
def test_avisa_la_caida_y_la_vuelta_una_sola_vez_por_racha():
    guard, _, _, sent = build()
    loop = FakeLoop("watch_remote_arch")

    caida(guard, loop, "watch_remote_arch")
    caida(guard, loop, "watch_remote_arch")

    assert len(sent) == 2, "solo el primer fallo de la racha avisa (caida+vuelta)"
    assert "se cayo" in sent[0] and "watch_remote_arch" in sent[0]
    assert "volvio a arrancar" in sent[1]


def test_si_discord_esta_caido_el_aviso_falla_pero_el_loop_vuelve():
    """El aviso viaja por el mismo Discord que se cayo: no puede ser fatal."""
    async def notify_roto(text):
        raise DiscordServerError("503 otra vez")

    guard, _, logs, _ = build(notify=notify_roto)
    loop = FakeLoop("watch_backups")

    ok = asyncio.run(guard.handle(loop, "watch_backups", DiscordServerError()))

    assert ok is True
    assert loop.starts == 1
    assert any("no se pudo avisar" in line for line in logs)


def test_sin_notify_configurado_igual_relanza():
    guard, _, _, _ = build(notify=None)
    loop = FakeLoop()
    assert asyncio.run(guard.handle(loop, "x", DiscordServerError())) is True
    assert loop.starts == 1


# --------------------------------------------------------------------------
# Casos borde del relanzamiento
# --------------------------------------------------------------------------
def test_no_duplica_el_loop_si_sigue_figurando_activo():
    """start() sobre un loop vivo lanzaria RuntimeError y duplicaria el trabajo."""
    guard, _, logs, _ = build()
    loop = FakeLoop(running=True)

    ok = asyncio.run(guard.handle(loop, "x", DiscordServerError()))

    assert ok is False
    assert loop.starts == 0
    assert any("no lo relanzo" in line for line in logs)


def test_espera_a_que_la_tarea_vieja_termine_de_bajar():
    guard, _, _, _ = build()
    loop = FakeLoop(stops_after=3)  # tarda 3 consultas en darse por detenido

    ok = asyncio.run(guard.handle(loop, "x", DiscordServerError()))

    assert ok is True
    assert loop.starts == 1


def test_un_start_que_falla_no_tumba_al_guardia():
    guard, _, logs, _ = build()
    loop = FakeLoop(start_error=RuntimeError("Task is already launched"))

    ok = asyncio.run(guard.handle(loop, "x", DiscordServerError()))

    assert ok is False
    assert any("no se pudo relanzar" in line for line in logs)


# --------------------------------------------------------------------------
# Cableado
# --------------------------------------------------------------------------
def test_arm_registra_el_handler_con_el_nombre_de_la_corrutina():
    guard, _, _, _ = build()
    loop = FakeLoop("watch_fail2ban")

    name = arm(loop, guard)

    assert name == "watch_fail2ban"
    assert loop.handler is not None


def test_el_handler_armado_relanza_el_loop():
    guard, _, _, _ = build()
    loop = FakeLoop("watch_docker_loops")
    arm(loop, guard)

    asyncio.run(loop.handler(DiscordServerError("503")))

    assert loop.starts == 1


def test_arm_all_arma_todos():
    guard, _, _, _ = build()
    loops = [FakeLoop("a"), FakeLoop("b"), FakeLoop("c")]

    names = arm_all(loops, guard)

    assert names == ["a", "b", "c"]
    assert all(loop.handler is not None for loop in loops)


def test_rearmar_es_idempotente():
    """on_ready se repite en cada reconexion."""
    guard, _, _, _ = build()
    loop = FakeLoop("a")

    arm(loop, guard)
    primero = loop.handler
    arm(loop, guard)

    assert loop.handler is not primero, "el handler nuevo pisa al anterior"
    asyncio.run(loop.handler(DiscordServerError()))
    assert loop.starts == 1, "y no se acumulan reinicios"


def test_los_defaults_del_modulo_son_los_documentados():
    assert loop_guard.BASE_DELAY == 30.0
    assert loop_guard.MAX_DELAY == 900.0
