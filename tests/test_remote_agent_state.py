import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch

import remote_agent


class StatePathTest(unittest.TestCase):
    """El agente es un proceso de un solo disparo: sin estado entre polls no
    hay ventana contra la cual medir CPU y las alarmas remotas se quedan sin
    nombre de proceso para siempre."""

    def test_runtime_dir_of_the_user_is_never_a_candidate(self):
        # /run/user/$UID es escribible, asi que pasa cualquier chequeo de
        # permisos, pero systemd lo borra al cerrarse la sesion SSH. Elegirlo
        # rompe la atribucion de procesos sin que falle nada.
        with tempfile.TemporaryDirectory() as home:
            with patch.dict(os.environ, {"XDG_CACHE_HOME": home}, clear=False):
                os.environ.pop("CENTINELA_AGENT_STATE", None)
                path = remote_agent._state_path()
        self.assertNotIn(f"/run/user/{os.getuid()}", path)

    def test_explicit_override_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "estado")
            with patch.dict(
                os.environ, {"CENTINELA_AGENT_STATE": target}, clear=False
            ):
                path = remote_agent._state_path()
        self.assertEqual(path, os.path.join(target, "proc-state.json"))

    def test_falls_back_to_cache_when_run_is_not_writable(self):
        real_makedirs = os.makedirs

        def only_outside_run(directory, **kwargs):
            if directory.startswith("/run"):
                raise PermissionError(directory)
            return real_makedirs(directory, exist_ok=True)

        with tempfile.TemporaryDirectory() as home:
            with patch.dict(os.environ, {"XDG_CACHE_HOME": home}, clear=False):
                os.environ.pop("CENTINELA_AGENT_STATE", None)
                with patch.object(
                    remote_agent.os, "makedirs", side_effect=only_outside_run
                ):
                    path = remote_agent._state_path()
                self.assertTrue(path.startswith(home))


class StateFreshnessTest(unittest.TestCase):
    """El fallback en cache sobrevive a un reinicio y el bot puede estar caido
    horas: en los dos casos la muestra vieja describe otra maquina u otra
    ventana, y publicarla seria peor que decir que no hay medicion."""

    def _attribution(self, state, boot):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "proc-state.json")
            with open(target, "w", encoding="utf-8") as handle:
                json.dump(state, handle)
            with patch.object(remote_agent, "_state_path", return_value=target):
                with patch.object(
                    remote_agent.psutil, "boot_time", return_value=boot
                ):
                    return remote_agent.process_attribution()

    def test_state_from_a_previous_boot_is_discarded(self):
        now = time.time()
        state = {
            "at": now - 60,
            "boot": now - 100_000,
            "procs": {str(os.getpid()): [0.0, 0.0]},
        }
        result = self._attribution(state, boot=now - 300)
        self.assertFalse(result["warm"])
        self.assertEqual(result["window_s"], 0.0)

    def test_state_older_than_the_cap_is_discarded(self):
        now = time.time()
        boot = now - 100_000
        state = {
            "at": now - remote_agent.MAX_STATE_AGE_S - 60,
            "boot": boot,
            "procs": {str(os.getpid()): [0.0, 0.0]},
        }
        result = self._attribution(state, boot=boot)
        self.assertFalse(result["warm"])
        self.assertEqual(result["window_s"], 0.0)

    def test_fresh_state_of_the_same_boot_is_used(self):
        now = time.time()
        boot = now - 100_000
        pid = os.getpid()
        created = remote_agent.psutil.Process(pid).create_time()
        state = {
            "at": now - 30,
            "boot": boot,
            "procs": {str(pid): [0.0, round(created, 3)]},
        }
        result = self._attribution(state, boot=boot)
        self.assertTrue(result["warm"])
        self.assertGreater(result["window_s"], 0.0)


if __name__ == "__main__":
    unittest.main()


class ResolveImageIdsTest(unittest.TestCase):
    """`docker ps` muestra el ID pelado cuando la etiqueta local se perdio."""

    def _resolve(self, containers, inspect_output, code=0):
        calls = []

        def fake_run(argv, timeout=None):
            calls.append(argv)
            return code, inspect_output

        with patch.object(remote_agent, "run", side_effect=fake_run):
            remote_agent.resolve_image_ids(containers)
        return calls

    def test_replaces_the_id_with_the_reference_it_was_started_with(self):
        containers = [
            {"name": "truly-valkey", "image": "1f84517eca8e"},
            {"name": "thinky-webui", "image": "18c1475e6362"},
        ]
        self._resolve(
            containers,
            "/truly-valkey|valkey/valkey:8.1\n"
            "/thinky-webui|ghcr.io/open-webui/open-webui:main",
        )
        self.assertEqual(containers[0]["image"], "valkey/valkey:8.1")
        self.assertEqual(containers[1]["image"], "ghcr.io/open-webui/open-webui:main")

    def test_does_not_touch_images_that_already_have_a_name(self):
        containers = [{"name": "truly-postgres", "image": "postgres:17.7"}]
        calls = self._resolve(containers, "")
        # Sin nada que resolver no se gasta un inspect.
        self.assertEqual(calls, [])
        self.assertEqual(containers[0]["image"], "postgres:17.7")

    def test_keeps_the_id_when_config_image_is_also_an_id(self):
        # Si lo levantaron por ID no hay nombre lindo que recuperar; mentir
        # seria peor que mostrar el ID.
        containers = [{"name": "raro", "image": "1f84517eca8e"}]
        self._resolve(containers, "/raro|1f84517eca8e")
        self.assertEqual(containers[0]["image"], "1f84517eca8e")

    def test_survives_a_failing_inspect(self):
        containers = [{"name": "truly-valkey", "image": "1f84517eca8e"}]
        self._resolve(containers, "no such object", code=1)
        self.assertEqual(containers[0]["image"], "1f84517eca8e")

    def test_a_real_reference_is_never_mistaken_for_an_id(self):
        for image in (
            "ghcr.io/open-webui/open-webui:main",
            "postgres:17.7",
            "aquasec/trivy:latest",
            "dev-api",
        ):
            self.assertIsNone(remote_agent.IMAGE_ID_RE.fullmatch(image), image)
