"""Tests de backup_monitor.

El reloj entra siempre por parámetro: `NOW` es fijo y las muestras se
construyen relativas a él. Un test de "hace cuánto" que use `datetime.now()`
real pasa hoy y falla a las 3 de la mañana.
"""

import os
import tempfile
import unittest
from datetime import datetime, timedelta

import backup_monitor as bm
from alerts import CRITICAL, NO_DATA, OK, WARNING

NOW = datetime(2026, 8, 3, 9, 0, 0)
POLICY = bm.BackupPolicy()


def epoch(delta):
    """Epoch de un instante `delta` antes de NOW."""
    return (NOW - delta).timestamp()


def sample(host, repo, value):
    return bm.Sample({"host": host, "repo": repo}, value)


class ParseInstantVectorTests(unittest.TestCase):
    def payload(self, result):
        return {"status": "success", "data": {"resultType": "vector", "result": result}}

    def test_parses_labels_and_values(self):
        samples = bm.parse_instant_vector(
            self.payload(
                [{"metric": {"host": "sempron", "repo": "mbp"}, "value": [1, "1234.5"]}]
            )
        )
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0].host, "sempron")
        self.assertEqual(samples[0].repo, "mbp")
        self.assertEqual(samples[0].value, 1234.5)

    def test_missing_labels_fall_back_without_raising(self):
        samples = bm.parse_instant_vector(self.payload([{"value": [1, "1"]}]))
        self.assertEqual((samples[0].host, samples[0].repo), ("?", "?"))

    def test_skips_nan_and_garbage_instead_of_failing(self):
        samples = bm.parse_instant_vector(
            self.payload(
                [
                    {"metric": {"host": "a"}, "value": [1, "NaN"]},
                    {"metric": {"host": "b"}, "value": [1, "no-soy-un-numero"]},
                    {"metric": {"host": "c"}, "value": []},
                    "esto no es un dict",
                    {"metric": {"host": "d"}, "value": [1, "7"]},
                ]
            )
        )
        self.assertEqual([s.host for s in samples], ["d"])

    def test_error_status_raises_with_the_reason(self):
        with self.assertRaises(bm.BackupMonitorError) as ctx:
            bm.parse_instant_vector({"status": "error", "error": "parse error"})
        self.assertIn("parse error", str(ctx.exception))

    def test_matrix_is_rejected(self):
        with self.assertRaises(bm.BackupMonitorError):
            bm.parse_instant_vector(
                {"status": "success", "data": {"resultType": "matrix", "result": []}}
            )

    def test_non_dict_payload_raises(self):
        with self.assertRaises(bm.BackupMonitorError):
            bm.parse_instant_vector("<html>proxy error</html>")


class FakeHttp:
    """Stub de HttpJson: devuelve por path, o levanta lo que se le indique."""

    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    async def get(self, path, params=None):
        self.calls.append((path, params))
        for prefix, response in self.responses.items():
            if path.startswith(prefix):
                if isinstance(response, Exception):
                    raise response
                return response
        raise bm.BackupMonitorError(f"404 {path}")


class PrometheusSourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_query_hits_the_configured_path(self):
        http = FakeHttp(
            {
                "/api/v1/query": {
                    "status": "success",
                    "data": {"resultType": "vector", "result": []},
                }
            }
        )
        source = bm.PrometheusSource(http)
        self.assertEqual(await source.query("up"), [])
        self.assertEqual(http.calls, [("/api/v1/query", {"query": "up"})])

    async def test_grafana_proxy_builds_the_datasource_path(self):
        source = bm.grafana_proxy_source("http://grafana:3000/", "tok", "prom-uid")
        self.assertEqual(
            source._path, "/api/datasources/proxy/uid/prom-uid/api/v1/query"
        )
        self.assertIn("prom-uid", source.origin)


class DiscoverDatasourceTests(unittest.IsolatedAsyncioTestCase):
    async def test_prefers_the_datasources_api_when_the_token_can_read_it(self):
        http = FakeHttp(
            {
                "/api/datasources": [
                    {"type": "loki", "uid": "loki-1"},
                    {"type": "prometheus", "uid": "prom-1"},
                ]
            }
        )
        self.assertEqual(await bm.discover_prometheus_datasource(http), "prom-1")

    async def test_falls_back_to_dashboard_panels_for_a_viewer_token(self):
        http = FakeHttp(
            {
                "/api/datasources": bm.BackupMonitorError("403"),
                "/api/search": [{"uid": "dash-1"}],
                "/api/dashboards/uid/dash-1": {
                    "dashboard": {
                        "panels": [
                            {"datasource": {"type": "prometheus", "uid": "${DS_PROM}"}},
                            {"datasource": {"type": "prometheus", "uid": "prom-real"}},
                        ]
                    }
                },
            }
        )
        self.assertEqual(await bm.discover_prometheus_datasource(http), "prom-real")

    async def test_raises_with_an_actionable_message_when_nothing_matches(self):
        http = FakeHttp(
            {
                "/api/datasources": bm.BackupMonitorError("403"),
                "/api/search": [],
            }
        )
        with self.assertRaises(bm.BackupMonitorError) as ctx:
            await bm.discover_prometheus_datasource(http)
        self.assertIn("BACKUP_PROMETHEUS_DATASOURCE", str(ctx.exception))


class JobStatusTests(unittest.TestCase):
    def job(self, **kwargs):
        base = {"host": "sempron", "repo": "server-mbp", "exit_code": 0}
        base.update(kwargs)
        return bm.JobStatus(**base)

    def test_recent_success_is_ok(self):
        job = self.job(last_success=NOW - timedelta(hours=6))
        self.assertEqual(job.assess(POLICY, NOW).severity, OK)

    def test_missed_run_warns(self):
        job = self.job(last_success=NOW - timedelta(hours=30))
        assessment = job.assess(POLICY, NOW)
        self.assertEqual(assessment.severity, WARNING)
        self.assertIn("1 d 6 h", assessment.reasons[0])

    def test_two_missed_runs_are_critical(self):
        job = self.job(last_success=NOW - timedelta(hours=50))
        self.assertEqual(job.assess(POLICY, NOW).severity, CRITICAL)

    def test_never_succeeded_is_critical(self):
        assessment = self.job(last_success=None).assess(POLICY, NOW)
        self.assertEqual(assessment.severity, CRITICAL)
        self.assertIn("sin ningún backup exitoso", assessment.reasons[0])

    def test_failed_run_warns_even_with_a_fresh_success(self):
        # El contrato conserva el último éxito real cuando el intento falla:
        # sin mirar el exit code, un backup que viene fallando hace 20 h se ve
        # verde hasta que cruza el umbral de antigüedad.
        job = self.job(last_success=NOW - timedelta(hours=20), exit_code=2)
        assessment = job.assess(POLICY, NOW)
        self.assertEqual(assessment.severity, WARNING)
        self.assertIn("exit 2", assessment.reasons[0])

    def test_failure_does_not_downgrade_a_critical_age(self):
        job = self.job(last_success=NOW - timedelta(hours=72), exit_code=2)
        self.assertEqual(job.assess(POLICY, NOW).severity, CRITICAL)


class RepoStatusTests(unittest.TestCase):
    def repo(self, **kwargs):
        base = {
            "host": "sempron",
            "tenant": "pentium",
            "last_restore_test": NOW - timedelta(days=2),
            "last_prune": NOW - timedelta(days=3),
            "last_check": NOW - timedelta(days=10),
            "canary_age_hours": 6,
        }
        base.update(kwargs)
        return bm.RepoStatus(**base)

    def test_healthy_repo(self):
        self.assertEqual(self.repo().assess(POLICY, NOW).severity, OK)

    def test_stale_restore_test_is_critical(self):
        assessment = self.repo(last_restore_test=NOW - timedelta(days=20)).assess(POLICY, NOW)
        self.assertEqual(assessment.severity, CRITICAL)

    def test_never_verified_warns(self):
        assessment = self.repo(last_restore_test=None).assess(POLICY, NOW)
        self.assertEqual(assessment.severity, WARNING)
        self.assertIn("nunca se verificó", assessment.reasons[0])

    def test_old_canary_flags_a_client_that_stopped_writing(self):
        # El caso que ninguna alerta de "el job falló" cubre: el repo está
        # impecable y el timer del cliente está muerto.
        assessment = self.repo(canary_age_hours=40).assess(POLICY, NOW)
        self.assertEqual(assessment.severity, WARNING)
        self.assertTrue(any("no está escribiendo" in r for r in assessment.reasons))

    def test_stale_prune_and_check_warn(self):
        assessment = self.repo(
            last_prune=NOW - timedelta(days=30), last_check=NOW - timedelta(days=90)
        ).assess(POLICY, NOW)
        self.assertEqual(assessment.severity, WARNING)
        self.assertEqual(len(assessment.reasons), 2)

    def test_missing_prune_and_check_do_not_warn_on_a_new_repo(self):
        # Un repo recién creado todavía no corrió su primer prune semanal.
        assessment = self.repo(last_prune=None, last_check=None).assess(POLICY, NOW)
        self.assertEqual(assessment.severity, OK)


class BuildReportTests(unittest.TestCase):
    def samples(self):
        return {
            bm.M_LAST_SUCCESS: [
                sample("sempron", "server-mbp", epoch(timedelta(hours=6))),
                sample("pentium", "sempron", 0),
            ],
            bm.M_EXIT_CODE: [
                sample("sempron", "server-mbp", 0),
                sample("pentium", "sempron", 1),
            ],
            bm.M_DURATION: [sample("sempron", "server-mbp", 930)],
            bm.M_CLIENT_SIZE: [sample("sempron", "server-mbp", 42 * 1024 ** 3)],
            bm.M_REPO_SIZE: [sample("sempron", "pentium", 12 * 1024 ** 3)],
            bm.M_REPO_ARCHIVES: [sample("sempron", "pentium", 17)],
            bm.M_RESTORE_TEST: [sample("sempron", "pentium", epoch(timedelta(days=1)))],
            bm.M_CANARY_AGE: [sample("sempron", "pentium", 5)],
            bm.M_PRUNE: [sample("sempron", "pentium", epoch(timedelta(days=2)))],
            bm.M_CHECK: [sample("sempron", "pentium", epoch(timedelta(days=9)))],
            bm.M_REPO_FREE: [bm.Sample({"host": "sempron"}, 400 * 1024 ** 3)],
        }

    def test_jobs_and_repos_are_assembled_from_labels(self):
        report = bm.build_report(self.samples(), POLICY, NOW)
        self.assertEqual([(j.host, j.repo) for j in report.jobs],
                         [("pentium", "sempron"), ("sempron", "server-mbp")])
        self.assertEqual([(r.host, r.tenant) for r in report.repos], [("sempron", "pentium")])
        self.assertEqual(report.hosts, ["pentium", "sempron"])

    def test_zero_timestamp_means_never_not_1970(self):
        report = bm.build_report(self.samples(), POLICY, NOW)
        never = next(j for j in report.jobs if j.host == "pentium")
        self.assertIsNone(never.last_success)
        self.assertEqual(never.exit_code, 1)

    def test_report_severity_is_the_worst_of_its_parts(self):
        report = bm.build_report(self.samples(), POLICY, NOW)
        self.assertEqual(report.severity, CRITICAL)  # pentium nunca respaldó

    def test_healthy_fleet_is_ok(self):
        samples = self.samples()
        samples[bm.M_LAST_SUCCESS] = [sample("sempron", "server-mbp", epoch(timedelta(hours=6)))]
        samples[bm.M_EXIT_CODE] = [sample("sempron", "server-mbp", 0)]
        report = bm.build_report(samples, POLICY, NOW)
        self.assertEqual(report.severity, OK)

    def test_empty_metrics_are_no_data_not_ok(self):
        report = bm.build_report({}, POLICY, NOW)
        self.assertTrue(report.is_empty)
        self.assertEqual(report.severity, NO_DATA)

    def test_query_errors_degrade_an_otherwise_healthy_report(self):
        samples = self.samples()
        samples[bm.M_LAST_SUCCESS] = [sample("sempron", "server-mbp", epoch(timedelta(hours=6)))]
        samples[bm.M_EXIT_CODE] = [sample("sempron", "server-mbp", 0)]
        report = bm.build_report(
            samples, POLICY, NOW, query_errors=("borg_repo_size_bytes: timeout",)
        )
        self.assertEqual(report.severity, WARNING)

    def test_free_space_thresholds(self):
        samples = self.samples()
        samples[bm.M_REPO_FREE] = [
            bm.Sample({"host": "sempron"}, 400 * 1024 ** 3),
            bm.Sample({"host": "server-mbp"}, 20 * 1024 ** 3),
            bm.Sample({"host": "pentium"}, 2 * 1024 ** 3),
        ]
        report = bm.build_report(samples, POLICY, NOW)
        self.assertEqual(
            report.free_space_issues(),
            [("pentium", 2 * 1024 ** 3, CRITICAL), ("server-mbp", 20 * 1024 ** 3, WARNING)],
        )


class FakeSource:
    def __init__(self, by_expr, origin="fake"):
        self.by_expr = by_expr
        self.origin = origin
        self.queries = []

    async def query(self, expr):
        self.queries.append(expr)
        for metric, result in self.by_expr.items():
            if metric in expr:
                if isinstance(result, Exception):
                    raise result
                return result
        return []


class CollectReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_wraps_every_metric_in_last_over_time(self):
        source = FakeSource({bm.M_LAST_SUCCESS: [sample("a", "b", epoch(timedelta(hours=1)))]})
        report = await bm.collect_report(source, POLICY, NOW)
        self.assertEqual(len(source.queries), len(bm.METRICS))
        self.assertIn(f"last_over_time({bm.M_LAST_SUCCESS}[14d])", source.queries)
        self.assertEqual(report.origin, "fake")
        self.assertEqual(len(report.jobs), 1)

    async def test_one_broken_query_does_not_lose_the_rest(self):
        source = FakeSource(
            {
                bm.M_LAST_SUCCESS: [sample("a", "b", epoch(timedelta(hours=1)))],
                bm.M_EXIT_CODE: bm.BackupMonitorError("timeout"),
            }
        )
        report = await bm.collect_report(source, POLICY, NOW)
        self.assertEqual(len(report.jobs), 1)
        self.assertEqual(len(report.query_errors), 1)
        self.assertIn("timeout", report.query_errors[0])

    async def test_total_failure_raises_the_real_error(self):
        class Broken:
            origin = "roto"

            async def query(self, expr):
                raise bm.BackupMonitorError("no pude conectar a http://prom:9090")

        with self.assertRaises(bm.BackupMonitorError) as ctx:
            await bm.collect_report(Broken(), POLICY, NOW)
        self.assertIn("no pude conectar", str(ctx.exception))

    async def test_lookback_comes_from_the_policy(self):
        source = FakeSource({})
        await bm.collect_report(source, bm.BackupPolicy(lookback_days=3), NOW)
        self.assertTrue(all("[3d]" in q for q in source.queries))


class RenderFleetTests(unittest.TestCase):
    def report(self, **kwargs):
        base = {
            "generated_at": NOW,
            "policy": POLICY,
            "jobs": (
                bm.JobStatus("sempron", "server-mbp", NOW - timedelta(hours=6), 0, 930, 1024),
                bm.JobStatus("pentium", "sempron", None, 1),
            ),
            "repos": (bm.RepoStatus("sempron", "pentium", 1024, 3, NOW, NOW, NOW, 4),),
            "free_bytes": {"sempron": 400 * 1024 ** 3},
        }
        base.update(kwargs)
        return bm.FleetBackupReport(**base)

    def test_no_metrics_says_what_to_check(self):
        view = bm.render_fleet(bm.FleetBackupReport(generated_at=NOW, policy=POLICY))
        self.assertEqual(view.color, bm.SEVERITY_COLOR[NO_DATA])
        self.assertIn("node-exporter-textfile", view.description)

    def test_renders_one_field_per_job_plus_repos_and_disk(self):
        view = bm.render_fleet(self.report())
        names = [f.name for f in view.fields]
        self.assertIn("🔴 pentium → sempron", names)
        self.assertIn("✅ sempron → server-mbp", names)
        self.assertIn("🗄 Repositorios", names)
        self.assertIn("💽 Espacio en los repo hosts", names)
        self.assertEqual(view.color, bm.SEVERITY_COLOR[CRITICAL])
        self.assertIn("1/2 backups al día", view.description)

    def test_host_filter_narrows_the_report(self):
        view = bm.render_fleet(self.report(), host_filter="pentium")
        job_fields = [f for f in view.fields if "→" in f.name]
        self.assertEqual([f.name for f in job_fields], ["🔴 pentium → sempron"])
        # El espacio libre de otro host no tiene por qué colarse en el filtro.
        self.assertNotIn("💽 Espacio en los repo hosts", [f.name for f in view.fields])

    def test_filtered_header_describes_what_is_shown(self):
        # Filtrar por el host sano no puede seguir mostrando el 🔴 de la flota.
        view = bm.render_fleet(self.report(), host_filter="sempron")
        self.assertEqual(view.color, bm.SEVERITY_COLOR[OK])
        self.assertIn("1/1 backup al día", view.description)

    def test_unknown_host_filter_says_so(self):
        view = bm.render_fleet(self.report(), host_filter="no-existe")
        self.assertIn("Ningún host coincide", view.description)

    def test_field_values_stay_within_discord_limits(self):
        many = tuple(
            bm.JobStatus(f"host{i}", "repo", None, 1) for i in range(40)
        )
        view = bm.render_fleet(self.report(jobs=many))
        self.assertLessEqual(len(view.fields), 25)
        self.assertTrue(all(len(f.value) <= 1024 for f in view.fields))
        self.assertTrue(all(len(f.name) <= 256 for f in view.fields))


class LocalRepoTests(unittest.TestCase):
    def test_inspect_reads_the_newest_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "index.42")
            with open(path, "w") as fh:
                fh.write("x" * 10)
            status = bm.inspect_local_repo(tmp, "sempron")
            self.assertTrue(status.exists)
            self.assertEqual(status.index_file, "index.42")
            self.assertEqual(status.size_bytes, 10)
            self.assertIsNotNone(status.last_modified)

    def test_missing_path_is_critical_not_a_crash(self):
        status = bm.inspect_local_repo("/no/existe", "x")
        self.assertTrue(status.configured)
        self.assertFalse(status.exists)
        self.assertEqual(status.assess(POLICY, NOW).severity, CRITICAL)

    def test_unconfigured_is_no_data(self):
        status = bm.inspect_local_repo("", "x")
        self.assertEqual(status.assess(POLICY, NOW).severity, NO_DATA)
        self.assertEqual(bm.render_local(status, POLICY, NOW).color, bm.SEVERITY_COLOR[NO_DATA])

    def test_repo_without_index_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            status = bm.inspect_local_repo(tmp, "x")
            self.assertEqual(status.assess(POLICY, NOW).severity, CRITICAL)

    def test_remote_payload_maps_to_the_same_model(self):
        status = bm.local_status_from_payload(
            {
                "configured": True,
                "exists": True,
                "index": "index.9",
                "last_timestamp": epoch(timedelta(hours=30)),
                "size": 2048,
            },
            label="arch",
        )
        self.assertEqual(status.index_file, "index.9")
        self.assertEqual(status.assess(POLICY, NOW).severity, WARNING)
        view = bm.render_local(status, POLICY, NOW)
        self.assertIn("arch", view.title)
        self.assertEqual(view.color, bm.SEVERITY_COLOR[WARNING])

    def test_empty_remote_payload_is_not_configured(self):
        self.assertFalse(bm.local_status_from_payload(None).configured)


class AlertStateTests(unittest.TestCase):
    def test_stays_quiet_when_everything_is_fine_at_boot(self):
        state = bm.AlertState()
        self.assertFalse(state.should_notify(OK, NOW))

    def test_notifies_on_every_transition(self):
        state = bm.AlertState()
        self.assertTrue(state.should_notify(WARNING, NOW))
        self.assertFalse(state.should_notify(WARNING, NOW + timedelta(hours=1)))
        self.assertTrue(state.should_notify(CRITICAL, NOW + timedelta(hours=2)))
        self.assertTrue(state.should_notify(OK, NOW + timedelta(hours=3)))

    def test_reminds_while_still_degraded(self):
        state = bm.AlertState(reminder=timedelta(hours=12))
        state.should_notify(CRITICAL, NOW)
        self.assertFalse(state.should_notify(CRITICAL, NOW + timedelta(hours=11)))
        self.assertTrue(state.should_notify(CRITICAL, NOW + timedelta(hours=12)))

    def test_never_reminds_while_ok(self):
        state = bm.AlertState(reminder=timedelta(hours=1))
        state.should_notify(WARNING, NOW)
        state.should_notify(OK, NOW + timedelta(hours=1))
        self.assertFalse(state.should_notify(OK, NOW + timedelta(days=5)))


class PolicyTests(unittest.TestCase):
    def test_defaults_match_the_designed_alert(self):
        # La alerta que el repo de backups define como la que importa.
        self.assertEqual(bm.BackupPolicy().stale_critical, timedelta(hours=48))

    def test_from_env_overrides_every_threshold(self):
        policy = bm.BackupPolicy.from_env(
            {
                "BACKUP_STALE_WARNING_HOURS": "12",
                "BACKUP_STALE_CRITICAL_HOURS": "24",
                "BACKUP_RESTORE_TEST_WARNING_DAYS": "3",
                "BACKUP_FREE_WARNING_GB": "5",
                "BACKUP_METRIC_LOOKBACK_DAYS": "2",
            }
        )
        self.assertEqual(policy.stale_warning, timedelta(hours=12))
        self.assertEqual(policy.stale_critical, timedelta(hours=24))
        self.assertEqual(policy.restore_test_warning, timedelta(days=3))
        self.assertEqual(policy.free_warning_bytes, 5 * 1024 ** 3)
        self.assertEqual(policy.lookback_days, 2)

    def test_from_env_ignores_unrelated_variables(self):
        self.assertEqual(bm.BackupPolicy.from_env({"PATH": "/usr/bin"}), bm.BackupPolicy())


class FormattingTests(unittest.TestCase):
    def test_age_reads_at_a_glance(self):
        self.assertEqual(bm.format_age(timedelta(seconds=45)), "45 s")
        self.assertEqual(bm.format_age(timedelta(minutes=12)), "12 min")
        self.assertEqual(bm.format_age(timedelta(hours=3, minutes=5)), "3 h 5 min")
        self.assertEqual(bm.format_age(timedelta(days=2, hours=4)), "2 d 4 h")
        self.assertEqual(bm.format_age(None), "nunca")

    def test_clock_skew_does_not_print_a_negative_age(self):
        self.assertEqual(bm.format_age(timedelta(seconds=-30)), "en el futuro")

    def test_bytes(self):
        self.assertEqual(bm.format_bytes(None), "—")
        self.assertEqual(bm.format_bytes(1536), "1.5 KB")
        self.assertEqual(bm.format_bytes(42 * 1024 ** 3), "42.0 GB")

    def test_worst_severity(self):
        self.assertEqual(bm.worst([]), OK)
        self.assertEqual(bm.worst([OK, WARNING, NO_DATA]), WARNING)
        self.assertEqual(bm.worst([WARNING, CRITICAL]), CRITICAL)


if __name__ == "__main__":
    unittest.main()
