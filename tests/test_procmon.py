import unittest
from unittest.mock import MagicMock, patch

import psutil

import procmon
from procmon import ProcessSampler, format_top


class FakeProc:
    """Process falso que imita la semantica que rompia el codigo viejo:
    cpu_percent() devuelve 0.0 la primera vez y el valor real despues."""

    def __init__(self, pid, name, cpu, mem=1.0, raises=None):
        self.pid = pid
        self.info = {"pid": pid}
        self._name, self._cpu, self._mem = name, cpu, mem
        self._raises = raises
        self.calls = 0

    def cpu_percent(self, interval=None):
        self.calls += 1
        if self._raises:
            raise self._raises
        return 0.0 if self.calls == 1 else self._cpu

    def oneshot(self):
        return MagicMock(__enter__=lambda s: None, __exit__=lambda s, *a: None)

    def name(self):
        return self._name

    def memory_percent(self):
        return self._mem


def with_procs(procs):
    return patch("procmon.psutil.process_iter", return_value=iter(procs))


class SamplerTests(unittest.TestCase):
    def test_primer_refresh_da_ceros_y_no_se_declara_caliente(self):
        # Esta es exactamente la condicion que producia la alerta inutil:
        # todos los procesos en 0.0. Ahora es detectable via warm().
        procs = [FakeProc(1, "systemd", 40.0), FakeProc(2, "python3", 80.0)]
        s = ProcessSampler()
        with with_procs(procs):
            s.refresh()
        self.assertFalse(s.warm())
        self.assertTrue(all(p["cpu"] == 0.0 for p in s.last_sample))

    def test_segundo_refresh_devuelve_tasas_reales(self):
        procs = [FakeProc(1, "systemd", 4.0), FakeProc(2, "python3", 80.0)]
        s = ProcessSampler()
        with with_procs(procs):
            s.refresh()
        with with_procs(procs):
            s.refresh()
        self.assertTrue(s.warm())
        self.assertEqual(s.top(1)[0]["name"], "python3")

    def test_reutiliza_los_objetos_process(self):
        # El corazon del arreglo: si se reconstruyen los Process en cada
        # muestreo, cpu_percent() vuelve a ser "la primera llamada" y devuelve
        # 0.0 para siempre.
        procs = [FakeProc(1, "python3", 50.0)]
        s = ProcessSampler()
        for _ in range(3):
            with with_procs(procs):
                s.refresh()
        self.assertEqual(procs[0].calls, 3)
        self.assertIs(s._procs[1], procs[0])

    def test_normaliza_por_nucleo(self):
        # psutil da 180% en un equipo de 2 nucleos; junto a un "sistema al 90%"
        # eso no cierra. Normalizado es 90%.
        procs = [FakeProc(1, "hog", 180.0)]
        s = ProcessSampler()
        with patch.object(procmon, "CPU_COUNT", 2):
            with with_procs(procs):
                s.refresh()
            with with_procs(procs):
                s.refresh()
        top = s.top(1)[0]
        self.assertEqual(top["cpu"], 90.0)
        self.assertEqual(top["cpu_raw"], 180.0)

    def test_memory_percent_none_no_rompe_el_sort(self):
        # El codigo viejo hacia sorted(key=lambda p: p.get(key, 0)) y comparar
        # None con float tira TypeError, llevandose puesta la alerta entera.
        procs = [FakeProc(1, "a", 10.0, mem=None), FakeProc(2, "b", 5.0, mem=3.0)]
        s = ProcessSampler()
        with with_procs(procs):
            s.refresh()
        with with_procs(procs):
            s.refresh()
        top = s.top(5, "ram")
        self.assertEqual(top[0]["name"], "b")

    def test_proceso_que_muere_durante_el_muestreo_se_saltea(self):
        procs = [
            FakeProc(1, "vivo", 10.0),
            FakeProc(2, "muerto", 99.0, raises=psutil.NoSuchProcess(2)),
        ]
        s = ProcessSampler()
        with with_procs(procs):
            s.refresh()
        with with_procs(procs):
            sample = s.refresh()
        self.assertEqual([p["name"] for p in sample], ["vivo"])

    def test_access_denied_no_corta_el_muestreo(self):
        procs = [
            FakeProc(1, "root-proc", 50.0, raises=psutil.AccessDenied(1)),
            FakeProc(2, "mio", 20.0),
        ]
        s = ProcessSampler()
        with with_procs(procs):
            s.refresh()
        with with_procs(procs):
            sample = s.refresh()
        self.assertEqual([p["name"] for p in sample], ["mio"])

    def test_limpia_los_procesos_muertos_del_cache(self):
        # Sin esto el dict crece sin techo en un host con procesos cortos.
        s = ProcessSampler()
        with with_procs([FakeProc(1, "a", 1.0), FakeProc(2, "b", 1.0)]):
            s.refresh()
        self.assertEqual(set(s._procs), {1, 2})
        with with_procs([FakeProc(1, "a", 1.0)]):
            s.refresh()
        self.assertEqual(set(s._procs), {1})

    def test_top_no_hace_io(self):
        # Las alertas llaman a top() y no pueden pagar un barrido de /proc.
        s = ProcessSampler()
        with with_procs([FakeProc(1, "a", 5.0)]):
            s.refresh()
        with patch("procmon.psutil.process_iter", side_effect=AssertionError("no I/O")):
            s.top(3)


class FormatTests(unittest.TestCase):
    def test_sin_procesos_devuelve_none(self):
        # None deja que quien llama omita el campo, en vez de publicar una
        # tabla vacia que parece una medicion.
        self.assertIsNone(format_top([]))

    def test_barra_no_desborda(self):
        linea = format_top([{"name": "x", "cpu": 999.0}])
        self.assertEqual(linea.count("█"), 10)


if __name__ == "__main__":
    unittest.main()
