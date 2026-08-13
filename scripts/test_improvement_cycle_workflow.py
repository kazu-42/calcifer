from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "improvement-cycle.yml"


class ImprovementCycleWorkflowContractTests(unittest.TestCase):
    def test_runs_weekly_and_manually_with_narrow_permissions(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("  schedule:\n", workflow)
        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertIn("  contents: read\n", workflow)
        self.assertIn("  issues: write\n", workflow)
        self.assertNotIn("pull_request:", workflow)

    def test_uses_pinned_checkout_and_body_files(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn(
            "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            workflow,
        )
        self.assertIn("python3 scripts/improvement_cycle.py", workflow)
        self.assertIn(
            'gh issue comment "${issue_number}" --body-file "${body}"', workflow
        )
        self.assertIn(
            'gh issue create --title "${title}" --label improvement-cycle '
            '--body-file "${body}"',
            workflow,
        )

    def test_suppresses_duplicate_snapshot_comments(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("calcifer-improvement-cycle-snapshot:v2", workflow)
        self.assertIn("already_exists", workflow)
        self.assertIn('if [[ "${already_exists}" == "true" ]]', workflow)


if __name__ == "__main__":
    unittest.main()
