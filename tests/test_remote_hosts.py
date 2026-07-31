import json
import os
import subprocess
import unittest
from unittest.mock import patch

import remote_agent
from remote_hosts import (
    RemoteHostClient,
    RemoteHostConfig,
    RemoteHostError,
)


def config():
    return RemoteHostConfig(
        key="arch",
        name="server-mbp",
        hostname="192.168.2.40",
        user="luca",
        identity_file="/keys/arch",
        known_hosts_file="/keys/known_hosts",
        timeout=12,
    )


class RemoteClientTests(unittest.TestCase):
    def test_disabled_env_has_no_remote(self):
        with patch.dict(
            os.environ,
            {
                "REMOTE_TEST_ENABLED": "false",
                "REMOTE_TEST_HOST": "192.0.2.1",
                "REMOTE_TEST_IDENTITY_FILE": "/key",
            },
            clear=False,
        ):
            self.assertIsNone(RemoteHostConfig.from_env("REMOTE_TEST"))

    def test_enabled_env_builds_config(self):
        with patch.dict(
            os.environ,
            {
                "REMOTE_TEST_ENABLED": "true",
                "REMOTE_TEST_HOST": "192.0.2.1",
                "REMOTE_TEST_IDENTITY_FILE": "/key",
                "REMOTE_TEST_TIMEOUT": "12",
            },
            clear=False,
        ):
            value = RemoteHostConfig.from_env("REMOTE_TEST")
        self.assertEqual(value.hostname, "192.0.2.1")
        self.assertEqual(value.timeout, 12)

    def test_unsafe_destination_is_rejected(self):
        with patch.dict(
            os.environ,
            {
                "REMOTE_TEST_ENABLED": "true",
                "REMOTE_TEST_HOST": "-oProxyCommand=sh",
                "REMOTE_TEST_IDENTITY_FILE": "/key",
            },
            clear=False,
        ):
            with self.assertRaises(RemoteHostError):
                RemoteHostConfig.from_env("REMOTE_TEST")

    def test_request_uses_fixed_ssh_options_and_json(self):
        calls = []

        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(
                argv, 0, stdout='{"ok":true,"cpu_percent":12.5}', stderr=""
            )

        result = RemoteHostClient(config(), runner=runner).request_sync("snapshot")
        self.assertEqual(result["cpu_percent"], 12.5)
        argv = calls[0][0]
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertEqual(argv[-2:], ["luca@192.168.2.40", "snapshot"])

    def test_arguments_are_shell_quoted_inside_one_forced_command(self):
        seen = []

        def runner(argv, **kwargs):
            seen.append(argv[-1])
            return subprocess.CompletedProcess(
                argv, 0, stdout='{"ok":true}', stderr=""
            )

        RemoteHostClient(config(), runner=runner).request_sync(
            "logs", "api.worker", 25
        )
        self.assertEqual(seen, ["logs api.worker 25"])

    def test_newlines_are_rejected_before_ssh(self):
        client = RemoteHostClient(
            config(),
            runner=lambda *a, **k: self.fail("runner should not be called"),
        )
        with self.assertRaises(RemoteHostError):
            client.request_sync("logs", "api\nwhoami")

    def test_non_json_response_fails_closed(self):
        def runner(argv, **kwargs):
            return subprocess.CompletedProcess(
                argv, 0, stdout="welcome banner", stderr=""
            )

        with self.assertRaises(RemoteHostError):
            RemoteHostClient(config(), runner=runner).request_sync("snapshot")

    def test_agent_error_is_propagated(self):
        def runner(argv, **kwargs):
            return subprocess.CompletedProcess(
                argv, 1, stdout='{"ok":false,"error":"denied"}', stderr=""
            )

        with self.assertRaisesRegex(RemoteHostError, "denied"):
            RemoteHostClient(config(), runner=runner).request_sync(
                "restart", "database"
            )


class ForcedAgentTests(unittest.TestCase):
    def test_unknown_operation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            remote_agent.dispatch(["shell", "id"])

    def test_restart_requires_explicit_allowlist(self):
        with patch.object(
            remote_agent,
            "CONFIG",
            {"allowed_restart": ["api"]},
        ):
            with self.assertRaises(PermissionError):
                remote_agent.docker_restart("database")

    def test_restart_never_uses_a_shell(self):
        with patch.object(
            remote_agent,
            "CONFIG",
            {"allowed_restart": ["api"]},
        ), patch.object(
            remote_agent,
            "run",
            return_value=(0, "api\n"),
        ) as run:
            result = remote_agent.docker_restart("api")
        self.assertTrue(result["ok"])
        run.assert_called_once_with(["docker", "restart", "api"], timeout=60)

    def test_malformed_resource_name_is_rejected(self):
        with self.assertRaises(ValueError):
            remote_agent.validate_name("api; shutdown")

    def test_invalid_temperature_channels_are_removed(self):
        reading = type("Reading", (), {"label": "bad", "current": -127.0})
        valid = type("Reading", (), {"label": "cpu", "current": 48.5})
        with patch.object(
            remote_agent.psutil,
            "sensors_temperatures",
            return_value={"chip": [reading, valid]},
        ):
            self.assertEqual(remote_agent.temperatures(), {"cpu": 48.5})

    def test_smart_uses_only_the_fixed_privileged_helper(self):
        helper_payload = json.dumps({
            "ok": True,
            "available": True,
            "device": "/dev/sda",
            "healthy": True,
            "output": "PASSED",
        })
        with patch.object(
            remote_agent.os, "geteuid", return_value=1000
        ), patch.object(
            remote_agent.shutil, "which", return_value="/usr/bin/tool"
        ), patch.object(
            remote_agent, "run", return_value=(0, helper_payload)
        ) as run:
            payload = remote_agent.smart_health()
        self.assertTrue(payload["healthy"])
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ["sudo", "-n"])
        self.assertEqual(argv[-1], "--smart-helper")

    def test_security_ignores_the_collector_key_fingerprint(self):
        line = json.dumps({
            "MESSAGE": (
                "Accepted publickey for luca from 192.168.2.10 port 22 "
                "ssh2: ED25519 SHA256:collector"
            ),
            "__REALTIME_TIMESTAMP": "1000000",
        })
        with patch.object(
            remote_agent,
            "CONFIG",
            {"ignored_ssh_key_fingerprints": ["SHA256:collector"]},
        ), patch.object(
            remote_agent, "run", return_value=(0, line)
        ):
            self.assertEqual(remote_agent.security_events(1)["events"], [])

    def test_main_always_returns_one_json_object(self):
        with patch.dict(
            remote_agent.os.environ,
            {"SSH_ORIGINAL_COMMAND": "hello"},
        ), patch("builtins.print") as output:
            self.assertEqual(remote_agent.main(), 0)
        payload = json.loads(output.call_args.args[0])
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["agent_version"], remote_agent.AGENT_VERSION)

    def test_malformed_original_command_is_json_error(self):
        with patch.dict(
            remote_agent.os.environ,
            {"SSH_ORIGINAL_COMMAND": "logs 'unterminated"},
        ), patch("builtins.print") as output:
            self.assertEqual(remote_agent.main(), 1)
        payload = json.loads(output.call_args.args[0])
        self.assertFalse(payload["ok"])


if __name__ == "__main__":
    unittest.main()
