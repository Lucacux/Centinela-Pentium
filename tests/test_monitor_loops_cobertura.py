"""Guardarrail: ningun tasks.loop puede quedar sin blindar.

El fix de los loops resilientes solo sirve mientras MONITOR_LOOPS este
completa. Un loop nuevo que no entre a la lista arranca sin manejador de
error y vuelve a tener el problema original: se detiene para siempre ante
un 503 y la unica senal es la ausencia de alertas.

Leemos main.py con ast en vez de importarlo porque importarlo exige token de
Discord y toda la configuracion del entorno.
"""

import ast
import pathlib

MAIN = pathlib.Path(__file__).resolve().parent.parent / "main.py"


def _arbol():
    return ast.parse(MAIN.read_text(encoding="utf-8"), filename=str(MAIN))


def _es_tasks_loop(decorador):
    """True si el decorador es @tasks.loop(...)."""
    if not isinstance(decorador, ast.Call):
        return False
    func = decorador.func
    return (
        isinstance(func, ast.Attribute)
        and func.attr == "loop"
        and isinstance(func.value, ast.Name)
        and func.value.id == "tasks"
    )


def loops_declarados():
    """Nombres de todas las funciones decoradas con @tasks.loop en main.py."""
    encontrados = set()
    for nodo in ast.walk(_arbol()):
        if isinstance(nodo, (ast.AsyncFunctionDef, ast.FunctionDef)):
            if any(_es_tasks_loop(d) for d in nodo.decorator_list):
                encontrados.add(nodo.name)
    return encontrados


def loops_en_la_lista():
    """Nombres que aparecen en la asignacion de MONITOR_LOOPS."""
    for nodo in ast.walk(_arbol()):
        if isinstance(nodo, ast.Assign):
            destinos = [t.id for t in nodo.targets if isinstance(t, ast.Name)]
            if "MONITOR_LOOPS" in destinos:
                if not isinstance(nodo.value, ast.List):
                    raise AssertionError("MONITOR_LOOPS dejo de ser una lista literal")
                return {e.id for e in nodo.value.elts if isinstance(e, ast.Name)}
    raise AssertionError("no existe MONITOR_LOOPS en main.py")


def test_hay_loops_que_analizar():
    """Si el parser deja de encontrar loops, el resto de los tests miente."""
    assert len(loops_declarados()) >= 15


def test_todos_los_loops_estan_blindados():
    faltan = loops_declarados() - loops_en_la_lista()
    assert not faltan, (
        "estos tasks.loop no estan en MONITOR_LOOPS y arrancarian sin "
        f"manejador de error: {sorted(faltan)}"
    )


def test_la_lista_no_nombra_loops_que_no_existen():
    sobran = loops_en_la_lista() - loops_declarados()
    assert not sobran, (
        f"MONITOR_LOOPS nombra cosas que ya no son tasks.loop: {sorted(sobran)}"
    )


def test_la_lista_se_define_despues_de_los_loops_que_nombra():
    """MONITOR_LOOPS se evalua al importar el modulo, no al llamar a on_ready.

    Definirla antes de los `@tasks.loop` que nombra es un NameError al arrancar
    el bot: el modulo ni siquiera importa. Los otros tests de este archivo no
    lo ven porque leen main.py con ast en vez de importarlo.
    """
    ultimo_loop = 0
    for nodo in ast.walk(_arbol()):
        if isinstance(nodo, (ast.AsyncFunctionDef, ast.FunctionDef)):
            if any(_es_tasks_loop(d) for d in nodo.decorator_list):
                ultimo_loop = max(ultimo_loop, nodo.lineno)

    linea_lista = None
    for nodo in ast.walk(_arbol()):
        if isinstance(nodo, ast.Assign):
            if any(t.id == "MONITOR_LOOPS"
                   for t in nodo.targets if isinstance(t, ast.Name)):
                linea_lista = nodo.lineno

    assert linea_lista is not None
    assert linea_lista > ultimo_loop, (
        f"MONITOR_LOOPS se define en la linea {linea_lista}, antes del ultimo "
        f"@tasks.loop (linea {ultimo_loop}): eso es un NameError al importar"
    )


def test_los_loops_se_arman_antes_de_arrancarlos():
    """arm_all tiene que correr antes del primer start() de on_ready.

    Al reves, un loop podria caerse en su primera iteracion sin manejador.
    """
    on_ready = None
    for nodo in ast.walk(_arbol()):
        if isinstance(nodo, ast.AsyncFunctionDef) and nodo.name == "on_ready":
            on_ready = nodo
            break
    assert on_ready is not None, "on_ready desaparecio de main.py"

    linea_arm = None
    linea_primer_start = None
    for nodo in ast.walk(on_ready):
        if isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Name):
            if nodo.func.id == "arm_all" and linea_arm is None:
                linea_arm = nodo.lineno
        if isinstance(nodo, ast.Call) and isinstance(nodo.func, ast.Attribute):
            if nodo.func.attr == "start":
                if linea_primer_start is None or nodo.lineno < linea_primer_start:
                    linea_primer_start = nodo.lineno

    assert linea_arm is not None, "on_ready ya no llama a arm_all"
    assert linea_primer_start is not None, "on_ready ya no arranca ningun loop"
    assert linea_arm < linea_primer_start, (
        "arm_all tiene que ir antes del primer start()"
    )
