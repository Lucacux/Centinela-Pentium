import unittest
from unittest.mock import patch

import runtime_discovery


class EndpointParsingTests(unittest.TestCase):
    def test_ipv4_and_ipv6_endpoint_notation(self):
        self.assertEqual(
            runtime_discovery.split_endpoint("0.0.0.0:8080"),
            ("0.0.0.0", "8080"),
        )
        self.assertEqual(
            runtime_discovery.split_endpoint("[::]:443"),
            ("::", "443"),
        )

    def test_wildcard_bind_is_rendered_as_host_address(self):
        self.assertEqual(
            runtime_discovery.display_ip("0.0.0.0", "192.168.2.10"),
            "192.168.2.10",
        )
        self.assertEqual(runtime_discovery.scope_of("127.0.0.1"), "local")


class ContainerDiscoveryTests(unittest.TestCase):
    def test_published_and_internal_ports_are_both_reported(self):
        inspected = [{
            "Name": "/api",
            "Config": {"Labels": {}, "ExposedPorts": {"9000/tcp": {}}},
            "State": {"Status": "running"},
            "NetworkSettings": {
                "Ports": {
                    "8000/tcp": [{
                        "HostIp": "0.0.0.0",
                        "HostPort": "18000",
                    }],
                    "9000/tcp": None,
                },
                "Networks": {"bridge": {"IPAddress": "172.17.0.2"}},
            },
        }]

        def fake_run(args, timeout=30):
            if args[:2] == ["docker", "info"]:
                return 0, ""
            if args[:3] == ["docker", "ps", "--format"]:
                return 0, "api\n"
            return 0, __import__("json").dumps(inspected)

        with patch.object(runtime_discovery, "run", side_effect=fake_run):
            rows = runtime_discovery.container_endpoints(
                "pentium", "192.168.2.10"
            )
        self.assertEqual(len(rows), 2)
        published = next(row for row in rows if row["port"] == "18000")
        internal = next(row for row in rows if row["port"] == "9000")
        self.assertEqual(published["ip"], "192.168.2.10")
        self.assertEqual(published["runtime"], "container")
        self.assertEqual(internal["ip"], "172.17.0.2")
        self.assertEqual(internal["runtime"], "container-internal")


class PrometheusRenderingTests(unittest.TestCase):
    def test_labels_are_escaped_and_endpoint_is_explicit(self):
        output = runtime_discovery.render([{
            "host": "pentium",
            "runtime": "systemd",
            "service": 'api"service',
            "state": "running",
            "bind": "0.0.0.0",
            "ip": "192.168.2.10",
            "port": "8080",
            "protocol": "tcp",
            "scope": "lan",
        }])
        self.assertIn('endpoint="192.168.2.10:8080/tcp"', output)
        self.assertIn('service="api\\"service"', output)


if __name__ == "__main__":
    unittest.main()
