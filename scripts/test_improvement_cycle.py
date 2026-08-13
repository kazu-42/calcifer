import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from scripts import improvement_cycle


class ImprovementCycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = datetime(2026, 8, 13, 12, 0, tzinfo=timezone.utc)
        self.issues = [
            {
                "number": 128,
                "title": "Run a hypothesis-driven continuous improvement program",
                "html_url": "https://github.com/kazu-42/calcifer/issues/128",
                "labels": [{"name": "improvement-cycle"}],
            },
            {
                "number": 130,
                "title": "Eliminate the target reservation promotion gap",
                "html_url": "https://github.com/kazu-42/calcifer/issues/130",
                "labels": [{"name": "reliability"}, {"name": "improvement-next"}],
            },
            {
                "number": 127,
                "title": "Prepare the next preview release",
                "html_url": "https://github.com/kazu-42/calcifer/pull/127",
                "labels": [],
                "pull_request": {
                    "url": "https://api.github.com/repos/kazu-42/calcifer/pulls/127"
                },
            },
        ]
        self.runs = [
            {
                "created_at": "2026-08-13T10:00:00Z",
                "status": "completed",
                "conclusion": "success",
            },
            {
                "created_at": "2026-08-12T10:00:00Z",
                "status": "completed",
                "conclusion": "failure",
            },
            {
                "created_at": "2026-08-11T10:00:00Z",
                "status": "in_progress",
                "conclusion": None,
            },
            {
                "created_at": "2026-08-01T10:00:00Z",
                "status": "completed",
                "conclusion": "failure",
            },
        ]
        self.releases = [
            {
                "draft": True,
                "immutable": False,
                "tag_name": "v0.1.0-alpha.5",
                "html_url": (
                    "https://github.com/kazu-42/calcifer/releases/tag/"
                    "v0.1.0-alpha.5"
                ),
            },
            {
                "draft": False,
                "immutable": True,
                "tag_name": "v0.1.0-alpha.4",
                "html_url": (
                    "https://github.com/kazu-42/calcifer/releases/tag/"
                    "v0.1.0-alpha.4"
                ),
            },
        ]

    def test_builds_one_deterministic_comment_snapshot(self) -> None:
        decision = improvement_cycle.build_decision(
            repository="kazu-42/calcifer",
            now=self.now,
            issues=self.issues,
            runs=self.runs,
            releases=self.releases,
        )

        self.assertEqual(decision.mode, "comment")
        self.assertEqual(decision.issue_number, 128)
        self.assertEqual(
            decision.marker,
            "calcifer-improvement-cycle-snapshot:v1 date=2026-08-13",
        )
        self.assertIn("| Open product issues | 2 |", decision.body)
        self.assertIn("| Open pull requests | 1 |", decision.body)
        self.assertIn(
            "| Main CI, last 7 days | 1 passed / 1 failed / 1 pending |",
            decision.body,
        )
        self.assertIn("[v0.1.0-alpha.4]", decision.body)
        self.assertIn("immutable", decision.body)
        self.assertIn(
            "[#130 Eliminate the target reservation promotion gap]", decision.body
        )
        self.assertNotIn("alpha.5", decision.body)

    def test_creates_a_cycle_when_none_is_open(self) -> None:
        issues = [issue for issue in self.issues if issue["number"] != 128]

        decision = improvement_cycle.build_decision(
            repository="kazu-42/calcifer",
            now=self.now,
            issues=issues,
            runs=self.runs,
            releases=[],
        )

        self.assertEqual(decision.mode, "create")
        self.assertIsNone(decision.issue_number)
        self.assertEqual(
            decision.title, "[Improvement cycle] 2026-08-13 repository health"
        )
        self.assertIn("No immutable public release found", decision.body)
        self.assertIn("## Decision gate", decision.body)
        self.assertIn("- [ ] Record the hypothesis", decision.body)
        self.assertIn("- [ ] Record the measured effect", decision.body)

    def test_rejects_ambiguous_active_or_next_issues(self) -> None:
        duplicate_cycle = self.issues + [
            {
                "number": 131,
                "title": "Another cycle",
                "html_url": "https://github.com/kazu-42/calcifer/issues/131",
                "labels": [{"name": "improvement-cycle"}],
            }
        ]
        with self.assertRaisesRegex(ValueError, "exactly one active improvement cycle"):
            improvement_cycle.build_decision(
                repository="kazu-42/calcifer",
                now=self.now,
                issues=duplicate_cycle,
                runs=self.runs,
                releases=self.releases,
            )

        duplicate_next = self.issues + [
            {
                "number": 129,
                "title": "Another candidate",
                "html_url": "https://github.com/kazu-42/calcifer/issues/129",
                "labels": [{"name": "improvement-next"}],
            }
        ]
        with self.assertRaisesRegex(ValueError, "exactly one next improvement"):
            improvement_cycle.build_decision(
                repository="kazu-42/calcifer",
                now=self.now,
                issues=duplicate_next,
                runs=self.runs,
                releases=self.releases,
            )

        active_is_next = [dict(issue) for issue in self.issues]
        active_is_next[0]["labels"] = [
            {"name": "improvement-cycle"},
            {"name": "improvement-next"},
        ]
        active_is_next[1]["labels"] = [{"name": "reliability"}]
        with self.assertRaisesRegex(ValueError, "active cycle cannot also be the next"):
            improvement_cycle.build_decision(
                repository="kazu-42/calcifer",
                now=self.now,
                issues=active_is_next,
                runs=self.runs,
                releases=self.releases,
            )

    def test_loads_paginated_github_api_shapes_and_rejects_invalid_items(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "issues.json"
            path.write_text(
                json.dumps([[self.issues[0]], [self.issues[1]]]),
                encoding="utf-8",
            )
            self.assertEqual(len(improvement_cycle.load_issue_pages(path)), 2)

            path.write_text(json.dumps([[{"number": True}]]), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "issue number"):
                improvement_cycle.load_issue_pages(path)

    def test_cli_writes_body_and_multiline_safe_github_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            issues = root / "issues.json"
            runs = root / "runs.json"
            releases = root / "releases.json"
            body = root / "body.md"
            outputs = root / "github-output"
            issues.write_text(json.dumps([self.issues]), encoding="utf-8")
            runs.write_text(
                json.dumps([{"workflow_runs": self.runs}]), encoding="utf-8"
            )
            releases.write_text(json.dumps([self.releases]), encoding="utf-8")

            exit_code = improvement_cycle.main(
                [
                    "--repository",
                    "kazu-42/calcifer",
                    "--now",
                    "2026-08-13T12:00:00Z",
                    "--issues-json",
                    str(issues),
                    "--runs-json",
                    str(runs),
                    "--releases-json",
                    str(releases),
                    "--body",
                    str(body),
                    "--github-output",
                    str(outputs),
                ]
            )

            self.assertEqual(exit_code, 0)
            expected = improvement_cycle.build_decision(
                repository="kazu-42/calcifer",
                now=self.now,
                issues=self.issues,
                runs=self.runs,
                releases=self.releases,
            ).body
            self.assertEqual(body.read_text(encoding="utf-8"), expected)
            self.assertEqual(
                outputs.read_text(encoding="utf-8"),
                "mode=comment\nissue_number=128\n"
                "marker=calcifer-improvement-cycle-snapshot:v1 "
                "date=2026-08-13\n",
            )


if __name__ == "__main__":
    unittest.main()
