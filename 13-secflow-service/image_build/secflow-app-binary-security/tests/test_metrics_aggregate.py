import asyncio
import os
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.metrics_aggregate import (
    AggregateMetadata,
    AggregatedMetricsPayload,
    PodTarget,
    ScrapeResult,
    _discover_binary_security_pods,
    _discover_local_pod_ip,
    aggregate_prometheus_samples,
    render_aggregated_metrics,
)


class MetricsAggregateTests(unittest.TestCase):
    def test_counter_and_local_gauges_are_summed(self):
        api_1 = ScrapeResult(
            target=PodTarget(pod_name="api-1", role="api", ip="10.0.0.1"),
            raw_text=(
                "# TYPE secflow_binary_security_api_requests_total counter\n"
                "secflow_binary_security_api_requests_total{method=\"GET\",path=\"/x\",status=\"200\"} 5\n"
                "# TYPE secflow_binary_security_active_workers gauge\n"
                "secflow_binary_security_active_workers{kind=\"task\"} 2\n"
            ),
        )
        api_2 = ScrapeResult(
            target=PodTarget(pod_name="api-2", role="api", ip="10.0.0.2"),
            raw_text=(
                "# TYPE secflow_binary_security_api_requests_total counter\n"
                "secflow_binary_security_api_requests_total{method=\"GET\",path=\"/x\",status=\"200\"} 7\n"
                "# TYPE secflow_binary_security_active_workers gauge\n"
                "secflow_binary_security_active_workers{kind=\"task\"} 3\n"
            ),
        )

        aggregated = aggregate_prometheus_samples([api_1, api_2])
        request_series = aggregated["secflow_binary_security_api_requests_total"]
        worker_series = aggregated["secflow_binary_security_active_workers"]

        self.assertEqual(
            12.0,
            request_series.samples[((("method", "GET"), ("path", "/x"), ("status", "200")))],
        )
        self.assertEqual(5.0, worker_series.samples[((("kind", "task"),))])

    def test_authoritative_reducer_metrics_prefer_reducer_max(self):
        worker = ScrapeResult(
            target=PodTarget(pod_name="worker-1", role="worker", ip="10.0.0.3"),
            raw_text=(
                "# TYPE secflow_binary_security_queue_depth gauge\n"
                "secflow_binary_security_queue_depth{queue=\"pending_tasks\"} 9\n"
            ),
        )
        reducer_1 = ScrapeResult(
            target=PodTarget(pod_name="reducer-1", role="reducer", ip="10.0.0.4"),
            raw_text=(
                "# TYPE secflow_binary_security_queue_depth gauge\n"
                "secflow_binary_security_queue_depth{queue=\"pending_tasks\"} 4\n"
            ),
        )
        reducer_2 = ScrapeResult(
            target=PodTarget(pod_name="reducer-2", role="reducer", ip="10.0.0.5"),
            raw_text=(
                "# TYPE secflow_binary_security_queue_depth gauge\n"
                "secflow_binary_security_queue_depth{queue=\"pending_tasks\"} 6\n"
            ),
        )

        aggregated = aggregate_prometheus_samples([worker, reducer_1, reducer_2])
        queue_series = aggregated["secflow_binary_security_queue_depth"]
        self.assertEqual(6.0, queue_series.samples[((("queue", "pending_tasks"),))])

    def test_render_aggregated_metrics_includes_metadata(self):
        payload = render_aggregated_metrics(
            {
                "secflow_binary_security_active_workers": SimpleNamespace(
                    metric_type="gauge",
                    help_text="Current workers",
                    samples={((("kind", "task"),)): 3.0},
                )
            },
            metadata=AggregateMetadata(
                attempted_by_role={"api": 4, "worker": 3, "reducer": 2},
                successful_by_role={"api": 4, "worker": 2, "reducer": 2},
                partial=True,
                generated_at=1234.5,
            ),
        ).decode("utf-8", errors="ignore")
        self.assertIn("secflow_binary_security_metrics_aggregate_scrape_targets", payload)
        self.assertIn("secflow_binary_security_metrics_aggregate_partial 1.0", payload)
        self.assertIn('secflow_binary_security_metrics_aggregate_role_expected{role="api"} 1.0', payload)
        self.assertIn('secflow_binary_security_metrics_aggregate_role_covered{role="worker"} 1.0', payload)

    def test_render_aggregated_metrics_includes_binary_security_health_metrics(self):
        payload = render_aggregated_metrics(
            {
                "secflow_binary_security_state_event_queue_depth": SimpleNamespace(
                    metric_type="gauge",
                    help_text="Queue depth",
                    samples={
                        ((("status", "pending"),)): 7.0,
                        ((("status", "dead_letter"),)): 2.0,
                    },
                ),
                "secflow_binary_security_state_event_oldest_age_seconds": SimpleNamespace(
                    metric_type="gauge",
                    help_text="Queue age",
                    samples={((("status", "pending"),)): 91.0},
                ),
                "secflow_binary_security_archive_jobs_by_status": SimpleNamespace(
                    metric_type="gauge",
                    help_text="Archive jobs",
                    samples={
                        ((("stage", "entry_analysis"), ("status", "queued"))): 3.0,
                        ((("stage", "entry_analysis"), ("status", "running"))): 1.0,
                        ((("stage", "dataflow_analysis"), ("status", "queued"))): 4.0,
                    },
                ),
                "secflow_binary_security_state_reducer_duration_seconds_sum": SimpleNamespace(
                    metric_type="histogram",
                    help_text="Reducer duration sum",
                    samples={(): 12.0},
                ),
                "secflow_binary_security_state_reducer_duration_seconds_count": SimpleNamespace(
                    metric_type="histogram",
                    help_text="Reducer duration count",
                    samples={(): 4.0},
                ),
                "secflow_binary_security_state_event_lag_seconds_sum": SimpleNamespace(
                    metric_type="histogram",
                    help_text="Event lag sum",
                    samples={(): 40.0},
                ),
                "secflow_binary_security_state_event_lag_seconds_count": SimpleNamespace(
                    metric_type="histogram",
                    help_text="Event lag count",
                    samples={(): 5.0},
                ),
                "secflow_binary_security_task_state_lock_wait_seconds_sum": SimpleNamespace(
                    metric_type="histogram",
                    help_text="Lock wait sum",
                    samples={(): 3.0},
                ),
                "secflow_binary_security_task_state_lock_wait_seconds_count": SimpleNamespace(
                    metric_type="histogram",
                    help_text="Lock wait count",
                    samples={(): 6.0},
                ),
                "secflow_binary_security_task_state_lock_held_seconds_sum": SimpleNamespace(
                    metric_type="histogram",
                    help_text="Lock held sum",
                    samples={(): 9.0},
                ),
                "secflow_binary_security_task_state_lock_held_seconds_count": SimpleNamespace(
                    metric_type="histogram",
                    help_text="Lock held count",
                    samples={(): 3.0},
                ),
                "secflow_binary_security_state_reducer_health": SimpleNamespace(
                    metric_type="gauge",
                    help_text="Reducer health",
                    samples={
                        ((("pod", "reducer-a"), ("signal", "loop_ok_at"))): 5600.0,
                        ((("pod", "reducer-a"), ("signal", "event_processed_at"))): 5605.0,
                        ((("pod", "reducer-a"), ("signal", "crash_at"))): 5610.0,
                        ((("pod", "reducer-a"), ("signal", "consecutive_crash_count"))): 2.0,
                    },
                ),
            },
            metadata=AggregateMetadata(
                attempted_by_role={"api": 2, "worker": 0, "reducer": 1},
                successful_by_role={"api": 2, "worker": 0, "reducer": 1},
                partial=False,
                generated_at=5678.9,
            ),
        ).decode("utf-8", errors="ignore")
        self.assertIn("secflow_binary_security_health_aggregate_partial 0.0", payload)
        self.assertIn("secflow_binary_security_health_pending_event_depth 7.0", payload)
        self.assertIn("secflow_binary_security_health_oldest_pending_age_seconds 91.0", payload)
        self.assertIn("secflow_binary_security_health_dead_letter_depth 2.0", payload)
        self.assertIn("secflow_binary_security_health_archive_queued_jobs 7.0", payload)
        self.assertIn("secflow_binary_security_health_archive_running_jobs 1.0", payload)
        self.assertIn("secflow_binary_security_health_reducer_avg_duration_seconds 3.0", payload)
        self.assertIn("secflow_binary_security_health_event_avg_lag_seconds 8.0", payload)
        self.assertIn("secflow_binary_security_health_lock_wait_avg_seconds 0.5", payload)
        self.assertIn("secflow_binary_security_health_lock_held_avg_seconds 3.0", payload)
        self.assertIn("secflow_binary_security_health_reducer_consecutive_crash_count 2.0", payload)
        self.assertRegex(payload, r"secflow_binary_security_health_reducer_loop_ok_age_seconds 78\.8[0-9]+")
        self.assertRegex(payload, r"secflow_binary_security_health_reducer_last_event_processed_age_seconds 73\.8[0-9]+")
        self.assertRegex(payload, r"secflow_binary_security_health_reducer_last_crash_age_seconds 68\.8[0-9]+")
        self.assertIn('secflow_binary_security_metrics_aggregate_role_covered{role="worker"} 0.0', payload)

    def test_aggregate_endpoint_returns_partial_result_when_some_scrapes_fail(self):
        from app import main

        fake_payload = AggregatedMetricsPayload(
            payload=b"# TYPE demo gauge\ndemo 1\n",
            content_type="text/plain; version=0.0.4; charset=utf-8",
            metadata=AggregateMetadata(
                attempted_by_role={"api": 2, "worker": 1, "reducer": 1},
                successful_by_role={"api": 1, "worker": 1, "reducer": 1},
                partial=True,
                generated_at=1234.5,
            ),
        )
        fake_aggregator = SimpleNamespace(aggregate=AsyncMock(return_value=fake_payload))
        with patch("app.main.get_metrics_aggregator", return_value=fake_aggregator):
            response = asyncio.run(main.aggregate_metrics_endpoint())
        self.assertEqual(200, response.status_code)
        self.assertIn("demo 1", response.body.decode("utf-8", errors="ignore"))

    def test_discover_binary_security_pods_reads_ready_service_endpoints(self):
        async def fake_fetch(path: str):
            if path.endswith("/endpoints/secflow-app-binary-security"):
                return {
                    "subsets": [
                        {
                            "addresses": [
                                {"ip": "10.0.0.1", "targetRef": {"name": "api-1"}},
                                {"ip": "10.0.0.2", "targetRef": {"name": "api-2"}},
                            ],
                            "ports": [{"port": 8080}],
                        }
                    ]
                }
            if path.endswith("/endpoints/secflow-app-binary-security-reducer"):
                return {
                    "subsets": [
                        {
                            "addresses": [
                                {"ip": "10.0.1.1", "targetRef": {"name": "reducer-1"}},
                            ],
                            "ports": [{"port": 8080}],
                        }
                    ]
                }
            return {}

        with patch("app.metrics_aggregate._fetch_k8s_resource", side_effect=fake_fetch):
            pods = asyncio.run(_discover_binary_security_pods())

        self.assertEqual(
            [
                PodTarget(pod_name="api-1", role="api", ip="10.0.0.1", port=8080),
                PodTarget(pod_name="api-2", role="api", ip="10.0.0.2", port=8080),
                PodTarget(pod_name="reducer-1", role="reducer", ip="10.0.1.1", port=8080),
            ],
            pods,
        )

    def test_local_fallback_only_applies_to_aggregated_roles(self):
        with patch.dict(os.environ, {"SECFLOW_BINARY_SECURITY_ROLE": "worker", "POD_IP": "10.0.0.9"}, clear=True):
            self.assertEqual([], _discover_local_pod_ip())
        with patch.dict(
            os.environ,
            {"SECFLOW_BINARY_SECURITY_ROLE": "api", "POD_IP": "10.0.0.8", "HOSTNAME": "api-fallback"},
            clear=True,
        ):
            self.assertEqual(
                [PodTarget(pod_name="api-fallback", role="api", ip="10.0.0.8", port=8080)],
                _discover_local_pod_ip(),
            )


if __name__ == "__main__":
    unittest.main()
