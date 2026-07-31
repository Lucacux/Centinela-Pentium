import json
import unittest
from unittest.mock import mock_open, patch

import netdiag
from netdiag import FAIL, OK, SKIP, Probe, default_gateway, diagnose, evaluate_speed, parse_speedtest


def probes(**layers):
    """probes(enlace=OK, wan=FAIL) -> lista de Probe."""
    return [Probe(name, state, f"detalle {name}") for name, state in layers.items()]


class DiagnoseTests(unittest.TestCase):
    def test_todo_ok(self):
        v = diagnose(probes(enlace=OK, wan=OK, dns=OK, http=OK, onu=OK))
        self.assertTrue(v["healthy"])
        self.assertIsNone(v["layer"])

    def test_enlace_caido_gana_sobre_el_resto(self):
        # Sin gateway todo lo de arriba falla por la misma razon; reportar cuatro
        # capas rotas seria ruido. La causa raiz es la primera de la escalera.
        v = diagnose(probes(enlace=FAIL, wan=FAIL, dns=FAIL))
        self.assertEqual(v["layer"], "enlace")
        self.assertIn("adentro de casa", v["summary"])

    def test_dns_caido_con_wan_sana_se_aisla(self):
        v = diagnose(probes(enlace=OK, wan=OK, dns=FAIL, onu=OK))
        self.assertEqual(v["layer"], "dns")
        self.assertFalse(v["healthy"])

    def test_captive_portal(self):
        # El caso que el ping-and-pray nunca vio: todo responde menos el trafico real.
        v = diagnose(probes(enlace=OK, wan=OK, dns=OK, http=FAIL, onu=OK))
        self.assertEqual(v["layer"], "http")

    def test_onu_manda_sobre_las_capas_de_arriba(self):
        # Si la fibra esta caida, que no haya WAN ni DNS es consecuencia.
        v = diagnose(probes(enlace=OK, wan=FAIL, dns=FAIL, onu=FAIL))
        self.assertEqual(v["layer"], "onu")

    def test_wan_caido_con_onu_sano_culpa_al_isp(self):
        v = diagnose(probes(enlace=OK, wan=FAIL, dns=FAIL, onu=OK))
        self.assertEqual(v["layer"], "wan")
        self.assertIn("ISP", v["summary"])

    def test_capa_skip_no_cuenta_como_falla(self):
        # Sin Guardian configurado la capa ONU queda en SKIP: eso no puede
        # inventar una falla que no existe.
        v = diagnose(probes(enlace=OK, wan=OK, dns=OK, http=OK, onu=SKIP))
        self.assertTrue(v["healthy"])


class GatewayTests(unittest.TestCase):
    ROUTE = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "enp2s0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\n"
        "enp2s0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
    )

    def test_parsea_gateway_little_endian(self):
        # 0102A8C0 -> 192.168.2.1
        with patch("builtins.open", mock_open(read_data=self.ROUTE)):
            self.assertEqual(default_gateway(), "192.168.2.1")

    def test_sin_ruta_default_devuelve_none(self):
        solo_lan = "Iface\tDestination\tGateway\tFlags\n enp2s0\t0002A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
        with patch("builtins.open", mock_open(read_data=solo_lan)):
            self.assertIsNone(default_gateway())


class ProbeLinkTests(unittest.TestCase):
    """El gateway real (192.168.2.1) descarta ICMP. Basar la capa 1 en ping
    daba 'enlace caido' permanente con internet andando: eso se regresiona."""

    def test_gateway_que_filtra_icmp_no_es_enlace_caido(self):
        with patch("netdiag.default_gateway", return_value="192.168.2.1"), \
             patch("netdiag.neighbour_state", return_value="REACHABLE"), \
             patch("netdiag._ping", return_value=(False, None)) as ping:
            p = netdiag.probe_link()
        self.assertEqual(p.state, OK)
        ping.assert_not_called()  # ARP REACHABLE alcanza: no se gasta un ping

    def test_arp_stale_se_confirma_por_tcp(self):
        with patch("netdiag.default_gateway", return_value="192.168.2.1"), \
             patch("netdiag.neighbour_state", return_value="STALE"), \
             patch("netdiag._tcp_open", side_effect=lambda h, p, **k: p == 53), \
             patch("netdiag._ping", return_value=(False, None)):
            p = netdiag.probe_link()
        self.assertEqual(p.state, OK)
        self.assertIn("TCP/53", p.detail)

    def test_solo_responde_icmp(self):
        with patch("netdiag.default_gateway", return_value="10.0.0.1"), \
             patch("netdiag.neighbour_state", return_value=None), \
             patch("netdiag._tcp_open", return_value=False), \
             patch("netdiag._ping", return_value=(True, 1.2)):
            p = netdiag.probe_link()
        self.assertEqual(p.state, OK)

    def test_nada_responde_y_sin_arp_es_enlace_fisico_caido(self):
        with patch("netdiag.default_gateway", return_value="10.0.0.1"), \
             patch("netdiag.neighbour_state", return_value=None), \
             patch("netdiag._tcp_open", return_value=False), \
             patch("netdiag._ping", return_value=(False, None)):
            p = netdiag.probe_link()
        self.assertEqual(p.state, FAIL)
        self.assertIn("enlace fisico", p.detail)

    def test_arp_stale_sin_respuesta_es_falla_pero_lo_aclara(self):
        with patch("netdiag.default_gateway", return_value="10.0.0.1"), \
             patch("netdiag.neighbour_state", return_value="STALE"), \
             patch("netdiag._tcp_open", return_value=False), \
             patch("netdiag._ping", return_value=(False, None)):
            p = netdiag.probe_link()
        self.assertEqual(p.state, FAIL)
        self.assertIn("STALE", p.detail)

    def test_sin_ruta_default(self):
        with patch("netdiag.default_gateway", return_value=None):
            p = netdiag.probe_link()
        self.assertEqual(p.state, FAIL)
        self.assertIn("ruta por defecto", p.detail)


class SpeedtestParseTests(unittest.TestCase):
    # Salida real del pentium (2026-07-31), recortada.
    RAW = json.dumps({
        "download": 24918608.2228256, "upload": 7717158.598232659, "ping": 66.058,
        "server": {"name": "Ipatinga", "country": "Brazil", "sponsor": "Vero Internet",
                   "id": "67942", "d": 3407.5977524963505},
        "client": {"ip": "45.163.249.80", "isp": "guayranet"},
    })

    def test_convierte_bits_a_mbps(self):
        r = parse_speedtest(self.RAW)
        self.assertAlmostEqual(r["down_mbps"], 24.918, places=2)
        self.assertAlmostEqual(r["up_mbps"], 7.717, places=2)
        self.assertEqual(r["server_id"], "67942")

    def test_json_roto_no_explota(self):
        self.assertIn("error", parse_speedtest("<html>502 Bad Gateway</html>"))

    def test_json_vacio_no_explota(self):
        self.assertIn("error", parse_speedtest(""))

    def test_campos_faltantes_no_explotan(self):
        r = parse_speedtest('{"download": 1000000}')
        self.assertNotIn("error", r)
        self.assertEqual(r["server_id"], "")


class EvaluateSpeedTests(unittest.TestCase):
    RESULT = {"down_mbps": 24.9}

    def test_sin_historia_no_opina(self):
        self.assertIsNone(evaluate_speed(self.RESULT, []))

    def test_pocas_muestras_solo_aprende(self):
        # Con 4 muestras un umbral seria adivinanza, no medicion.
        v = evaluate_speed(self.RESULT, [24, 25, 26, 24])
        self.assertEqual(v["verdict"], "baseline")

    def test_velocidad_normal(self):
        v = evaluate_speed(self.RESULT, [24, 25, 26, 24, 25, 27])
        self.assertEqual(v["verdict"], "ok")

    def test_mitad_de_la_mediana_es_lento(self):
        v = evaluate_speed({"down_mbps": 10.0}, [24, 25, 26, 24, 25, 27])
        self.assertEqual(v["verdict"], "slow")
        self.assertGreater(v["pct"], 50)

    def test_degradado_es_su_propia_categoria(self):
        v = evaluate_speed({"down_mbps": 17.0}, [24, 25, 26, 24, 25, 27])
        self.assertEqual(v["verdict"], "degraded")

    def test_error_de_speedtest_no_se_evalua(self):
        self.assertIsNone(evaluate_speed({"error": "timeout"}, [24, 25, 26, 24, 25]))

    def test_mediana_ignora_el_outlier(self):
        # Una corrida fallida a 0.5 Mbps no debe arrastrar la referencia hacia
        # abajo y hacer que lo lento parezca normal despues.
        v = evaluate_speed({"down_mbps": 24.0}, [0.5, 24, 25, 26, 24, 25])
        self.assertEqual(v["verdict"], "ok")


class ProbeGuardianTests(unittest.TestCase):
    def test_sin_url_queda_en_skip(self):
        with patch.object(netdiag, "GUARDIAN_URL", ""):
            p, data = netdiag.probe_guardian()
        self.assertEqual(p.state, SKIP)
        self.assertIsNone(data)

    def test_onu_caido(self):
        payload = json.dumps({"onu_up": False, "wan_up": False})
        with patch.object(netdiag, "GUARDIAN_URL", "http://x:8099"), \
             patch("netdiag.subprocess.run") as run:
            run.return_value.stdout = payload
            p, data = netdiag.probe_guardian()
        self.assertEqual(p.state, FAIL)
        self.assertIn("ONU no responde", p.detail)

    def test_onu_vivo_pero_sin_wan_culpa_al_isp(self):
        payload = json.dumps({"onu_up": True, "wan_up": False})
        with patch.object(netdiag, "GUARDIAN_URL", "http://x:8099"), \
             patch("netdiag.subprocess.run") as run:
            run.return_value.stdout = payload
            p, data = netdiag.probe_guardian()
        self.assertEqual(p.state, FAIL)
        self.assertIn("ISP", p.detail)

    def test_guardian_caido_no_rompe_el_diagnostico(self):
        # El Guardian es opcional: si no contesta, se pierde una capa, no todo.
        with patch.object(netdiag, "GUARDIAN_URL", "http://x:8099"), \
             patch("netdiag.subprocess.run", side_effect=OSError("unreachable")):
            p, data = netdiag.probe_guardian()
        self.assertEqual(p.state, SKIP)


if __name__ == "__main__":
    unittest.main()
