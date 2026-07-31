import unittest
from datetime import datetime, timedelta

from alerts import ALARM, CRITICAL, NO_DATA, OK, WARNING, Alarm, AlarmEngine, in_quiet_hours


def alarm(**kw):
    kw.setdefault("name", "cpu")
    kw.setdefault("title", "CPU")
    kw.setdefault("threshold", 90)
    return Alarm(**kw)


def feed(a, valores, t0=None):
    """Alimenta N muestras espaciadas un minuto. Devuelve los eventos."""
    t0 = t0 or datetime(2026, 7, 31, 12, 0)
    out = []
    for i, v in enumerate(valores):
        ev = a.evaluate(v, t0 + timedelta(minutes=i))
        if ev:
            out.append(ev)
    return out


class NofMTests(unittest.TestCase):
    def test_un_pico_aislado_no_dispara(self):
        # El caso que mas ruido hacia: un muestreo al 91% mandaba DISCO CRITICO.
        a = alarm(datapoints=2, periods=3)
        eventos = feed(a, [10, 95, 10, 10])
        self.assertEqual(a.state, OK)
        self.assertEqual([e for e in eventos if e["to"] == ALARM], [])

    def test_dos_de_tres_dispara(self):
        a = alarm(datapoints=2, periods=3)
        feed(a, [10, 95, 96])
        self.assertEqual(a.state, ALARM)

    def test_no_espera_a_llenar_la_ventana_si_ya_hay_evidencia(self):
        # Con N muestras en falta el problema ya es real; esperar a completar M
        # solo retrasa el aviso.
        a = alarm(datapoints=2, periods=5)
        feed(a, [95, 96])
        self.assertEqual(a.state, ALARM)

    def test_umbral_menor_que(self):
        a = alarm(threshold=10, comparison="lt", datapoints=2, periods=3)
        feed(a, [50, 5, 4])
        self.assertEqual(a.state, ALARM)


class RecoveryTests(unittest.TestCase):
    def test_la_recuperacion_notifica(self):
        # Antes llegaba "CPU CRITICA" y nunca "CPU normalizada".
        a = alarm(datapoints=2, periods=3)
        eventos = feed(a, [95, 96, 10, 10, 10])
        self.assertEqual(a.state, OK)
        self.assertEqual(eventos[-1]["to"], OK)
        self.assertEqual(eventos[-1]["from"], ALARM)

    def test_la_recuperacion_informa_cuanto_duro(self):
        a = alarm(datapoints=2, periods=3)
        eventos = feed(a, [95, 96, 10, 10, 10])
        self.assertGreater(eventos[-1]["duration_s"], 0)

    def test_no_notifica_ok_al_arrancar(self):
        # Arrancar sano no es una noticia: INSUFFICIENT_DATA -> OK es el estado
        # normal de un bot que acaba de levantar, no una recuperacion.
        a = alarm(datapoints=2, periods=3)
        eventos = feed(a, [10, 10, 10])
        self.assertEqual(eventos, [])
        self.assertEqual(a.state, OK)


class NoDataTests(unittest.TestCase):
    def test_sin_datos_no_es_lo_mismo_que_cero(self):
        # Un sensor de temperatura que desaparece no es un equipo frio.
        a = alarm(datapoints=2, periods=3)
        feed(a, [None, None, None])
        self.assertEqual(a.state, NO_DATA)

    def test_pasar_de_ok_a_sin_datos_avisa(self):
        a = alarm(datapoints=2, periods=3)
        eventos = feed(a, [10, 10, 10, None, None, None])
        self.assertEqual(a.state, NO_DATA)
        self.assertEqual(eventos[-1]["to"], NO_DATA)

    def test_huecos_sueltos_no_borran_la_evidencia(self):
        a = alarm(datapoints=2, periods=3)
        feed(a, [95, None, 96])
        self.assertEqual(a.state, ALARM)


class CooldownTests(unittest.TestCase):
    def test_no_repite_mientras_sigue_en_alarma(self):
        a = alarm(datapoints=2, periods=3, cooldown_min=60)
        eventos = feed(a, [95] * 10)
        self.assertEqual(len(eventos), 1)

    def test_recuerda_cuando_vence_el_cooldown(self):
        a = alarm(datapoints=2, periods=3, cooldown_min=5)
        t0 = datetime(2026, 7, 31, 12, 0)
        feed(a, [95, 95], t0)
        ev = a.evaluate(95, t0 + timedelta(minutes=30))
        self.assertIsNotNone(ev)
        self.assertEqual(ev["kind"], "reminder")

    def test_el_cooldown_no_tapa_una_transicion(self):
        # Bug viejo: el cooldown de una hora se comia el aviso de recuperacion.
        a = alarm(datapoints=2, periods=3, cooldown_min=600)
        eventos = feed(a, [95, 95, 1, 1, 1])
        self.assertEqual(eventos[-1]["to"], OK)


class QuietHoursTests(unittest.TestCase):
    def test_franja_normal(self):
        self.assertTrue(in_quiet_hours(datetime(2026, 7, 31, 3, 0), 1, 8))
        self.assertFalse(in_quiet_hours(datetime(2026, 7, 31, 14, 0), 1, 8))

    def test_franja_que_cruza_medianoche(self):
        self.assertTrue(in_quiet_hours(datetime(2026, 7, 31, 23, 30), 22, 6))
        self.assertTrue(in_quiet_hours(datetime(2026, 7, 31, 2, 0), 22, 6))
        self.assertFalse(in_quiet_hours(datetime(2026, 7, 31, 12, 0), 22, 6))

    def test_de_noche_lo_critico_pasa_igual(self):
        a = alarm(severity=CRITICAL)
        self.assertTrue(a.should_notify_now(None, datetime(2026, 7, 31, 3, 0)))

    def test_de_noche_el_warning_se_calla(self):
        a = alarm(severity=WARNING)
        self.assertFalse(a.should_notify_now(None, datetime(2026, 7, 31, 3, 0)))


class EngineTests(unittest.TestCase):
    def test_solo_evalua_las_metricas_entregadas(self):
        # Una alarma sin metrica en este ciclo conserva su estado en vez de
        # comerse un hueco falso.
        eng = AlarmEngine([alarm(name="cpu"), alarm(name="ram")])
        eng.evaluate({"cpu": 10})
        self.assertEqual(eng.alarms["ram"].state, NO_DATA)
        self.assertEqual(eng.alarms["cpu"].state, OK)

    def test_lo_critico_se_reporta_primero(self):
        eng = AlarmEngine([
            alarm(name="ram", severity=WARNING, datapoints=1, periods=1),
            alarm(name="disco", severity=CRITICAL, datapoints=1, periods=1),
        ])
        eventos = eng.evaluate({"ram": 99, "disco": 99})
        self.assertEqual(eventos[0]["alarm"].name, "disco")

    def test_metrica_desconocida_se_ignora(self):
        eng = AlarmEngine([alarm(name="cpu")])
        self.assertEqual(eng.evaluate({"inexistente": 1}), [])

    def test_snapshot_expone_el_estado(self):
        eng = AlarmEngine([alarm(name="cpu", datapoints=1, periods=1)])
        eng.evaluate({"cpu": 99})
        self.assertEqual(eng.snapshot()[0]["state"], ALARM)


class ActionTests(unittest.TestCase):
    def test_la_accion_se_describe_pero_no_se_ejecuta_sola(self):
        # En esta infra el control lo tiene el usuario: por defecto se propone.
        a = alarm(action="reiniciar nginx")
        self.assertFalse(a.auto)
        self.assertEqual(a.action, "reiniciar nginx")


if __name__ == "__main__":
    unittest.main()
