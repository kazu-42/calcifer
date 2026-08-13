import json
import tempfile
import unittest
from pathlib import Path

from scripts import failover_scorecard

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "ci.yml"


class FailoverScorecardTests(unittest.TestCase):
    def test_required_matrix_is_complete_and_stable(self) -> None:
        self.assertEqual(
            tuple(failover_scorecard.EXPECTED_CASES),
            (
                "available_continuation",
                "rounded_100_without_reached_type",
                "stale_usage",
                "unknown_usage",
                "authentication_failure",
                "provider_timeout",
                "network_error",
                "provider_overload",
                "malformed_protocol",
                "natural_exit_75",
                "pool_exhausted",
                "pool_all_unknown",
                "pool_busy",
                "pool_no_eligible",
                "membership_change",
                "policy_change",
                "source_crash_recovery",
                "target_crash_recovery",
                "target_contention",
                "cooldown_exhaustion",
            ),
        )

    def test_case_schema_rejects_extra_fields_and_sensitive_shapes(self) -> None:
        case = {
            "scenario": "stale_usage",
            "outcome_code": "codex_exhaustion_revalidation_failed",
            "source_alias": "source",
            "target_alias": None,
            "generation_count": 1,
            "provider_start_count": 1,
            "recovery_result": "none",
            "duration_bucket": "lt_1_s",
        }
        failover_scorecard.validate_case(case)

        with self.assertRaisesRegex(ValueError, "schema allowlist"):
            failover_scorecard.validate_case({**case, "token": "private"})
        with self.assertRaisesRegex(ValueError, "fixed local alias"):
            failover_scorecard.validate_case(
                {**case, "source_alias": "owner@example.invalid"}
            )
        with self.assertRaisesRegex(ValueError, "fixed outcome"):
            failover_scorecard.validate_case(
                {**case, "outcome_code": "/private/workspace"}
            )

    def test_expected_result_detects_controlled_integration_regression(self) -> None:
        case = {
            "scenario": "stale_usage",
            "outcome_code": "codex_exhaustion_revalidation_failed",
            "source_alias": "source",
            "target_alias": None,
            "generation_count": 1,
            "provider_start_count": 2,
            "recovery_result": "none",
            "duration_bucket": "lt_1_s",
        }
        with self.assertRaisesRegex(ValueError, "provider_start_count"):
            failover_scorecard.validate_expected_result(case)

    def test_scorecard_writer_is_canonical_and_private(self) -> None:
        cases = []
        for scenario, expected in failover_scorecard.EXPECTED_CASES.items():
            cases.append(
                {
                    "scenario": scenario,
                    **expected,
                    "source_alias": "source",
                    "target_alias": (
                        "target" if expected["generation_count"] == 2 else None
                    ),
                    "duration_bucket": "lt_1_s",
                }
            )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "scorecard.json"
            failover_scorecard.write_scorecard(
                output,
                source_commit="a" * 40,
                cases=cases,
                controlled_regression_detected=True,
            )
            document = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(
                set(document),
                {
                    "schema_version",
                    "source_commit",
                    "scenario_count",
                    "expected_outcome_agreement_percent",
                    "unexpected_provider_starts",
                    "p95_duration_bucket",
                    "controlled_regression_detected",
                    "cases",
                },
            )
            self.assertEqual(document["schema_version"], 1)
            self.assertEqual(document["source_commit"], "a" * 40)
            self.assertEqual(document["scenario_count"], 20)
            self.assertEqual(document["expected_outcome_agreement_percent"], 100)
            self.assertEqual(document["unexpected_provider_starts"], 0)
            self.assertEqual(document["p95_duration_bucket"], "lt_1_s")
            self.assertTrue(document["controlled_regression_detected"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertTrue(output.read_bytes().endswith(b"\n"))
            encoded = output.read_text(encoding="utf-8")
            for sensitive_shape in ("@", "/private/", "token", "workspace_id"):
                self.assertNotIn(sensitive_shape, encoded)

    def test_scorecard_rejects_a_p95_outside_the_runtime_budget(self) -> None:
        cases = []
        for index, (scenario, expected) in enumerate(
            failover_scorecard.EXPECTED_CASES.items()
        ):
            cases.append(
                {
                    "scenario": scenario,
                    **expected,
                    "source_alias": "source",
                    "target_alias": (
                        "target" if expected["generation_count"] == 2 else None
                    ),
                    "duration_bucket": "gte_5_s" if index < 2 else "lt_1_s",
                }
            )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "p95 exceeded"):
                failover_scorecard.write_scorecard(
                    Path(directory) / "scorecard.json",
                    source_commit="b" * 40,
                    cases=cases,
                    controlled_regression_detected=True,
                )

    def test_ci_publishes_the_exact_head_redacted_scorecard(self) -> None:
        workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("  failover-scorecard:\n")
        end = workflow.index("  test:\n", start)
        job = workflow[start:end]

        self.assertIn("name: Failover Scorecard", job)
        self.assertIn(
            "SOURCE_COMMIT: ${{ github.event.pull_request.head.sha || github.sha }}",
            job,
        )
        self.assertIn(
            "ref: ${{ github.event.pull_request.head.sha || github.sha }}", job
        )
        self.assertIn("--features internal-failover-scorecard", job)
        self.assertIn("scripts/failover_scorecard.py", job)
        self.assertIn("name: failover-scorecard-v1", job)
        self.assertIn("retention-days: 14", job)


if __name__ == "__main__":
    unittest.main()
