import unittest
from unittest.mock import patch

import docker_ops
from docker_ops import group_services, resolve_service, restart_service, service_of


def task(name, status="Up 7 minutes", image="img:latest", ports=""):
    return {
        "name": name,
        "service": service_of(name),
        "status": status,
        "image": image,
        "ports": ports,
        "running": status.startswith("Up"),
    }


class ServiceNameTests(unittest.TestCase):
    def test_strips_swarm_task_suffix(self):
        self.assertEqual(
            service_of("discordbots-mediabot-glzzul.1.s4aflfw1qys6bsqvep6j1yfia"),
            "discordbots-mediabot-glzzul",
        )

    def test_leaves_plain_container_untouched(self):
        self.assertEqual(service_of("grafana"), "grafana")

    def test_does_not_eat_names_with_dots(self):
        # Un contenedor comun llamado "foo.1.2" no es una task de Swarm: el id
        # de task son 20+ caracteres alfanumericos, no un numero.
        self.assertEqual(service_of("foo.1.2"), "foo.1.2")

    def test_survives_a_second_redeploy(self):
        a = service_of("api.1.aaaaaaaaaaaaaaaaaaaa")
        b = service_of("api.1.bbbbbbbbbbbbbbbbbbbb")
        self.assertEqual(a, b)


class GroupServicesTests(unittest.TestCase):
    def test_collapses_stale_task_left_by_redeploy(self):
        # El caso real: la task nueva corriendo y la vieja muerta al lado. Antes
        # se veian como dos contenedores, uno rojo, y el rojo asustaba.
        grouped = group_services([
            task("mediabot.1.x3zz6obk2ifedshugu1vq0ysx", "Up 13 hours"),
            task("mediabot.1.qz898d18swg6vltxuamqfj19", "Exited (137) 21 hours ago"),
        ])
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["service"], "mediabot")
        self.assertEqual(grouped[0]["stale"], 1)
        self.assertTrue(grouped[0]["current"]["running"])

    def test_running_task_wins_even_if_listed_last(self):
        grouped = group_services([
            task("api.1.aaaaaaaaaaaaaaaaaaaa", "Exited (0) 2 hours ago"),
            task("api.1.bbbbbbbbbbbbbbbbbbbb", "Up 5 minutes"),
        ])
        self.assertEqual(grouped[0]["current"]["name"], "api.1.bbbbbbbbbbbbbbbbbbbb")
        self.assertEqual(grouped[0]["stale"], 1)

    def test_all_dead_keeps_newest_and_stays_down(self):
        grouped = group_services([
            task("api.1.aaaaaaaaaaaaaaaaaaaa", "Exited (1) 5 minutes ago"),
            task("api.1.bbbbbbbbbbbbbbbbbbbb", "Exited (1) 1 hour ago"),
        ])
        self.assertEqual(len(grouped), 1)
        self.assertFalse(grouped[0]["current"]["running"])
        self.assertEqual(grouped[0]["current"]["name"], "api.1.aaaaaaaaaaaaaaaaaaaa")

    def test_keeps_distinct_services_apart(self):
        grouped = group_services([
            task("api.1.aaaaaaaaaaaaaaaaaaaa"),
            task("web.1.bbbbbbbbbbbbbbbbbbbb"),
        ])
        self.assertEqual({g["service"] for g in grouped}, {"api", "web"})
        self.assertEqual([g["stale"] for g in grouped], [0, 0])


class ResolveServiceTests(unittest.TestCase):
    def setUp(self):
        self.tasks = [
            task("discordbots-mediabot-glzzul.1.s4aflfw1qys6bsqvep6j1yfia"),
            task("grafana"),
        ]

    def _resolve(self, name):
        with patch.object(docker_ops, "list_tasks", return_value=self.tasks):
            return resolve_service(name)

    def test_matches_by_service_name(self):
        svc, cur = self._resolve("discordbots-mediabot-glzzul")
        self.assertEqual(svc["service"], "discordbots-mediabot-glzzul")
        self.assertTrue(cur["name"].startswith("discordbots-mediabot-glzzul."))

    def test_matches_by_substring_so_you_can_type_it_on_a_phone(self):
        svc, _ = self._resolve("mediabot")
        self.assertEqual(svc["service"], "discordbots-mediabot-glzzul")

    def test_still_accepts_the_full_task_name(self):
        svc, _ = self._resolve("discordbots-mediabot-glzzul.1.s4aflfw1qys6bsqvep6j1yfia")
        self.assertEqual(svc["service"], "discordbots-mediabot-glzzul")

    def test_unknown_name_is_rejected(self):
        # Esta es la allowlist real: lo que no existe no llega nunca a docker.
        self.assertEqual(self._resolve("no-existe"), (None, None))

    def test_injection_attempt_is_rejected(self):
        svc, cur = self._resolve("grafana; rm -rf /")
        self.assertIsNone(svc)
        self.assertIsNone(cur)


class RestartServiceTests(unittest.TestCase):
    def test_swarm_service_uses_force_update_not_restart(self):
        calls = []

        def fake(args, timeout=30):
            calls.append(args)
            return True, "ok"

        with patch.object(docker_ops, "docker_cmd", side_effect=fake):
            restart_service("api", task("api.1.aaaaaaaaaaaaaaaaaaaa"))

        self.assertEqual(calls[0][:2], ["service", "inspect"])
        self.assertEqual(calls[1], ["service", "update", "--force", "api"])

    def test_plain_container_falls_back_to_docker_restart(self):
        calls = []

        def fake(args, timeout=30):
            calls.append(args)
            if args[0] == "service":
                return False, "no such service"
            return True, "grafana"

        with patch.object(docker_ops, "docker_cmd", side_effect=fake):
            restart_service("grafana", task("grafana"))

        self.assertEqual(calls[-1], ["restart", "grafana"])


class NoShellTests(unittest.TestCase):
    def test_docker_cmd_never_uses_a_shell(self):
        seen = {}

        def fake_run(argv, **kwargs):
            seen["argv"] = argv
            seen["kwargs"] = kwargs

            class P:
                returncode = 0
                stdout = "ok"
                stderr = ""
            return P()

        with patch.object(docker_ops.shutil, "which", return_value="/usr/bin/docker"), \
                patch.object(docker_ops.subprocess, "run", side_effect=fake_run):
            docker_ops.docker_cmd(["logs", "foo; rm -rf /"])

        self.assertIsInstance(seen["argv"], list)
        self.assertNotIn("shell", seen["kwargs"])
        # El payload viaja como UN argumento, no como dos comandos.
        self.assertEqual(seen["argv"], ["docker", "logs", "foo; rm -rf /"])


if __name__ == "__main__":
    unittest.main()
