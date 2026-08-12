"""Guardarrail: ningun tasks.loop puede quedar sin blindar.

El fix de los loops resilientes solo sirve mientras MONITOR_LOOPS este
completa. Un loop nuevo que no entre a la lista arranca sin manejador de
error y vuelve a tener el problema original: se detiene para siempre ante un
503, y la unica senal es la ausencia de alertas.

Leemos main.py con ast en vez de importarlo porque importarlo exige token de
Discord y toda la configuracion del entorno.
"""

import ast
import pathlib
import unittest

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


def _loops_declarados():
    """Nombre y linea de cada funcion decorada con @tasks.loop en main.py."""
    encontrados = {}
    for nodo in ast.walk(_arbol()):
        if isinstance(nodo, (ast.AsyncFunctionDef, ast.FunctionDef)):
            if any(_es_tasks_loop(d) for d in nodo.decorator_list):
                encontrados[nodo.name] = nodo.lineno
    return encontrados


def _asignacion_de_la_lista():
    """Nombres y linea de la asignacion de MONITOR_LOOPS."""
    for nodo in ast.walk(_arbol()):
        if isinstance(nodo, ast.Assign):
            destinos = [t.id for t in nodo.targets if isinstance(t, ast.Name)]
            if "MONITOR_LOOPS" in destinos:
                if not isinstance(nodo.value, ast.List):
                    raise AssertionError(
                        "MONITOR_LOOPS dejo de ser una lista literal")
                nombres = {e.id for e in nodo.value.elts
                           if isinstance(e, ast.Name)}
                return nombres, nodo.lineno
    raise AssertionError("no existe MONITOR_LOOPS en main.py")


class CoberturaDeLoopsTests(unittest.TestCase):
    def test_hay_loops_que_analizar(self):
        """Si el parser deja de encontrarlos, el resto de los tests miente."""
        self.assertGreaterEqual(len(_loops_declarados()), 15)

    def test_todos_los_loops_estan_blindados(self):
        en_la_lista, _ = _asignacion_de_la_lista()
        faltan = set(_loops_declarados()) - en_la_lista
        self.assertFalse(faltan, (
            "estos tasks.loop no estan en MONITOR_LOOPS y arrancarian sin "
            f"manejador de error: {sorted(faltan)}"
        ))

    def test_la_lista_no_nombra_loops_que_no_existen(self):
        en_la_lista, _ = _asignacion_de_la_lista()
        sobran = en_la_lista - set(_loops_declarados())
        self.assertFalse(sobran, (
            f"MONITOR_LOOPS nombra cosas que ya no son tasks.loop: {sorted(sobran)}"
        ))


class OrdenDeDefinicionTests(unittest.TestCase):
    def test_la_lista_se_define_despues_de_los_loops_que_nombra(self):
        """MONITOR_LOOPS se evalua al importar el modulo, no al llamar on_ready.

        Definirla antes de los `@tasks.loop` que nombra es un NameError al
        arrancar el bot: el modulo ni siquiera importa. Los otros tests no lo
        ven porque leen main.py con ast en vez de importarlo.
        """
        declarados = _loops_declarados()
        ultimo_loop = max(declarados.values())
        _, linea_lista = _asignacion_de_la_lista()

        self.assertGreater(linea_lista, ultimo_loop, (
            f"MONITOR_LOOPS se define en la linea {linea_lista}, antes del "
            f"ultimo @tasks.loop (linea {ultimo_loop}): NameError al importar"
        ))

    def test_los_loops_se_arman_antes_de_arrancarlos(self):
        """arm_all tiene que correr antes del primer start() de on_ready.

        Al reves, un loop podria caerse en su primera iteracion sin manejador.
        """
        on_ready = None
        for nodo in ast.walk(_arbol()):
            if isinstance(nodo, ast.AsyncFunctionDef) and nodo.name == "on_ready":
                on_ready = nodo
                break
        self.assertIsNotNone(on_ready, "on_ready desaparecio de main.py")

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

        self.assertIsNotNone(linea_arm, "on_ready ya no llama a arm_all")
        self.assertIsNotNone(linea_primer_start,
                             "on_ready ya no arranca ningun loop")
        self.assertLess(linea_arm, linea_primer_start,
                        "arm_all tiene que ir antes del primer start()")


if __name__ == "__main__":
    unittest.main()
