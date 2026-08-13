from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowContractTests(unittest.TestCase):
    def test_release_contract_changes_trigger_the_release_dry_run(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("  pull_request:\n")
        end = workflow.index("  push:\n", start)
        pull_request_trigger = workflow[start:end]

        self.assertEqual(
            pull_request_trigger.count("      - scripts/test_release_workflow.py\n"),
            1,
        )

    def test_tag_publish_path_requires_runtime_acceptance_gates(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("          required_checks=(\n")
        end = workflow.index("          )\n", start)
        required_checks = tuple(
            line.strip()[1:-1]
            for line in workflow[start:end].splitlines()
            if line.strip().startswith('"')
        )

        self.assertEqual(
            required_checks,
            (
                "Quality",
                "Test (ubuntu-latest)",
                "Test (macos-latest)",
                "Test (windows-latest)",
                "Pinned Codex Package",
                "Failover Scorecard",
                "MSRV (1.85.0)",
            ),
        )

    def test_release_bundle_waits_for_the_exact_source_failover_scorecard(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        scorecard_start = workflow.index("  failover-scorecard:\n")
        build_start = workflow.index("  build:\n", scorecard_start)
        scorecard_job = workflow[scorecard_start:build_start]
        bundle_start = workflow.index("  bundle:\n", build_start)
        sign_start = workflow.index("  sign:\n", bundle_start)
        bundle_job = workflow[bundle_start:sign_start]

        self.assertIn("SOURCE_COMMIT: ${{ needs.validate.outputs.source_commit }}", scorecard_job)
        self.assertIn("--features internal-failover-scorecard", scorecard_job)
        self.assertIn("scripts/failover_scorecard.py", scorecard_job)
        self.assertIn("name: failover-scorecard-release-v1", scorecard_job)
        self.assertNotIn("name: release-failover-scorecard", scorecard_job)
        self.assertIn("      - failover-scorecard\n", bundle_job)

    def test_tag_publish_path_rejects_lightweight_tags(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        dry_run_gate = workflow.index('if [[ "${IS_PUBLISH_EVENT}" != "true" ]]')
        tag_lookup = workflow.index('tag_ref_json="$(gh api')
        start = workflow.index('tag_ref_type="$(jq -r')
        end = workflow.index("printf 'tag_ref_digest=", start)
        tag_gate = workflow[start:end]

        self.assertLess(dry_run_gate, tag_lookup)
        self.assertIn("exit 0", workflow[dry_run_gate:tag_lookup])
        self.assertIn('[[ "${tag_ref_type}" != "tag" ]]', tag_gate)
        self.assertNotIn('"commit"', tag_gate)
        self.assertIn("must be an annotated Git tag object", tag_gate)

    def test_tag_release_signs_the_complete_archive_set_in_protected_environment(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        sign_start = workflow.index("  sign:\n")
        publish_start = workflow.index("  publish:\n", sign_start)
        sign_job = workflow[sign_start:publish_start]
        publish_job = workflow[publish_start:]

        self.assertIn("environment: release-signing", sign_job)
        self.assertIn("MINISIGN_PRIVATE_KEY: ${{ secrets.MINISIGN_PRIVATE_KEY }}", sign_job)
        self.assertIn("9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73", sign_job)
        self.assertIn('"${minisign}" -S -W', sign_job)
        self.assertIn('"${minisign}" -Vm', sign_job)
        self.assertIn("name: signed-release-bundle", sign_job)
        self.assertIn("      - sign\n", publish_job)
        self.assertIn("name: signed-release-bundle", publish_job)
        self.assertIn(
            "9a599b48ba6eb7b1e80f12f36b94ceca7c00b7a5173c95c3efc88d9822957e73",
            publish_job,
        )
        self.assertIn('"${minisign}" -Vm', publish_job)

    def test_release_contract_changes_include_distribution_generators(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")
        start = workflow.index("  pull_request:\n")
        end = workflow.index("  push:\n", start)
        pull_request_trigger = workflow[start:end]

        for path in (
            "scripts/generate_homebrew_formula.py",
            "scripts/test_generate_homebrew_formula.py",
            "scripts/test_binstall_metadata.py",
        ):
            self.assertIn(f"      - {path}\n", pull_request_trigger)


if __name__ == "__main__":
    unittest.main()
