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

    def test_tag_publish_path_requires_the_pinned_codex_package_gate(self) -> None:
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
                "MSRV (1.85.0)",
            ),
        )

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


if __name__ == "__main__":
    unittest.main()
