from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowContractTests(unittest.TestCase):
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
