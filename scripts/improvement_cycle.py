#!/usr/bin/env python3
"""Render a deterministic, public-data-only repository improvement snapshot."""

from __future__ import annotations

import argparse
import json
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Sequence


REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
MAX_INPUT_BYTES = 8 * 1024 * 1024
CYCLE_LABEL = "improvement-cycle"
NEXT_LABEL = "improvement-next"
SNAPSHOT_SCHEMA = "calcifer-improvement-cycle-snapshot:v1"


@dataclass(frozen=True)
class Decision:
    mode: str
    issue_number: int | None
    title: str | None
    marker: str
    body: str


def _read_json(path: Path) -> object:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"input must be a regular file: {path}")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input exceeds the {MAX_INPUT_BYTES}-byte limit: {path}")
    try:
        return json.loads(path.read_bytes())
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ValueError(f"input must be valid UTF-8 JSON: {path}") from error


def _page_list(document: object, field: str) -> list[object]:
    if not isinstance(document, list):
        raise ValueError(f"{field} response must be a paginated JSON array")
    return document


def _validate_issue(issue: object) -> dict[str, object]:
    if not isinstance(issue, dict):
        raise ValueError("issue entry must be an object")
    number = issue.get("number")
    if type(number) is not int or number <= 0:
        raise ValueError("issue number must be a positive integer")
    title = issue.get("title")
    url = issue.get("html_url")
    labels = issue.get("labels")
    if not isinstance(title, str) or not title or "\n" in title or "\r" in title:
        raise ValueError("issue title must be one non-empty line")
    if not isinstance(url, str) or not url.startswith("https://github.com/"):
        raise ValueError("issue URL must be an HTTPS GitHub URL")
    if not isinstance(labels, list) or any(
        not isinstance(label, dict) or not isinstance(label.get("name"), str)
        for label in labels
    ):
        raise ValueError("issue labels must be GitHub label objects")
    return issue


def load_issue_pages(path: Path) -> list[dict[str, object]]:
    pages = _page_list(_read_json(path), "issues")
    issues: list[dict[str, object]] = []
    for page in pages:
        if not isinstance(page, list):
            raise ValueError("each issues page must be an array")
        issues.extend(_validate_issue(issue) for issue in page)
    return issues


def load_run_pages(path: Path) -> list[dict[str, object]]:
    pages = _page_list(_read_json(path), "workflow runs")
    runs: list[dict[str, object]] = []
    for page in pages:
        if not isinstance(page, dict) or not isinstance(
            page.get("workflow_runs"), list
        ):
            raise ValueError("each workflow-runs page must contain workflow_runs")
        for run in page["workflow_runs"]:
            if not isinstance(run, dict):
                raise ValueError("workflow run entry must be an object")
            runs.append(run)
    return runs


def load_release_pages(path: Path) -> list[dict[str, object]]:
    pages = _page_list(_read_json(path), "releases")
    releases: list[dict[str, object]] = []
    for page in pages:
        if not isinstance(page, list):
            raise ValueError("each releases page must be an array")
        for release in page:
            if not isinstance(release, dict):
                raise ValueError("release entry must be an object")
            releases.append(release)
    return releases


def _labels(issue: dict[str, object]) -> set[str]:
    labels = issue.get("labels")
    if not isinstance(labels, list):
        raise ValueError("issue labels must be an array")
    names: set[str] = set()
    for label in labels:
        if not isinstance(label, dict) or not isinstance(label.get("name"), str):
            raise ValueError("issue labels must be GitHub label objects")
        names.add(label["name"])
    return names


def _is_pull_request(issue: dict[str, object]) -> bool:
    return "pull_request" in issue


def _parse_github_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _markdown_title(value: str) -> str:
    return value.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]")


def _issue_link(issue: dict[str, object]) -> str:
    number = issue["number"]
    title = issue["title"]
    url = issue["html_url"]
    if (
        type(number) is not int
        or not isinstance(title, str)
        or not isinstance(url, str)
    ):
        raise ValueError("validated issue fields were lost")
    return f"[#{number} {_markdown_title(title)}]({url})"


def _ci_counts(
    runs: Iterable[dict[str, object]], *, cutoff: datetime
) -> tuple[int, int, int]:
    passed = 0
    failed = 0
    pending = 0
    for run in runs:
        created_at = _parse_github_time(
            run.get("created_at"), "workflow run created_at"
        )
        if created_at < cutoff:
            continue
        status = run.get("status")
        conclusion = run.get("conclusion")
        if status != "completed":
            pending += 1
        elif conclusion == "success":
            passed += 1
        else:
            failed += 1
    return passed, failed, pending


def _latest_immutable_release(releases: Iterable[dict[str, object]]) -> str:
    for release in releases:
        if release.get("draft") is not False or release.get("immutable") is not True:
            continue
        tag = release.get("tag_name")
        url = release.get("html_url")
        if (
            not isinstance(tag, str)
            or not isinstance(url, str)
            or not url.startswith("https://github.com/")
        ):
            raise ValueError("immutable release must have a tag and HTTPS GitHub URL")
        return f"[{_markdown_title(tag)}]({url}) (immutable)"
    return "No immutable public release found"


def build_decision(
    *,
    repository: str,
    now: datetime,
    issues: Sequence[dict[str, object]],
    runs: Sequence[dict[str, object]],
    releases: Sequence[dict[str, object]],
) -> Decision:
    if REPOSITORY_PATTERN.fullmatch(repository) is None:
        raise ValueError("repository must use the owner/name form")
    if now.tzinfo is None:
        raise ValueError("now must include a timezone")
    now = now.astimezone(timezone.utc)
    validated_issues = [_validate_issue(issue) for issue in issues]
    product_issues = [
        issue for issue in validated_issues if not _is_pull_request(issue)
    ]
    pull_requests = [issue for issue in validated_issues if _is_pull_request(issue)]
    active_cycles = [issue for issue in product_issues if CYCLE_LABEL in _labels(issue)]
    next_issues = [issue for issue in product_issues if NEXT_LABEL in _labels(issue)]
    if len(active_cycles) > 1:
        raise ValueError("expected zero or exactly one active improvement cycle")
    if len(next_issues) > 1:
        raise ValueError("expected zero or exactly one next improvement")
    if active_cycles and next_issues and active_cycles[0] is next_issues[0]:
        raise ValueError("the active cycle cannot also be the next improvement")

    passed, failed, pending = _ci_counts(runs, cutoff=now - timedelta(days=7))
    next_issue = (
        _issue_link(next_issues[0])
        if next_issues
        else "No issue carries `improvement-next`"
    )
    release = _latest_immutable_release(releases)
    date = now.date().isoformat()
    marker = f"{SNAPSHOT_SCHEMA} date={date}"
    mode = "comment" if active_cycles else "create"
    issue_number = active_cycles[0]["number"] if active_cycles else None
    if issue_number is not None and type(issue_number) is not int:
        raise ValueError("validated active-cycle number was lost")
    title = (
        None
        if active_cycles
        else f"[Improvement cycle] {date} repository health"
    )

    body = "\n".join(
        (
            f"<!-- {marker} -->",
            f"## Automated repository health snapshot — {date}",
            "",
            "This snapshot uses public GitHub repository metadata only. "
            "It does not close issues, merge pull requests, deploy code, or infer "
            "runtime success.",
            "",
            "| Signal | Baseline |",
            "| --- | ---: |",
            f"| Open product issues | {len(product_issues)} |",
            f"| Open pull requests | {len(pull_requests)} |",
            "| Main CI, last 7 days | "
            f"{passed} passed / {failed} failed / {pending} pending |",
            f"| Latest immutable release | {release} |",
            f"| Recommended next issue | {next_issue} |",
            "",
            "## Decision gate",
            "",
            "- [ ] Record the hypothesis and the user-visible or operational "
            "outcome it should improve.",
            "- [ ] Record the baseline query or reproduction before implementation.",
            "- [ ] Set a numeric target and a rollback or recovery condition.",
            "- [ ] Implement the smallest change that can test the hypothesis.",
            "- [ ] Verify focused tests, full CI, review threads, and the exact "
            "merged commit.",
            "- [ ] Record the measured effect using the same baseline method.",
            "- [ ] Decide: keep, revise, or revert; then move `improvement-next` "
            "to one successor.",
            "",
        )
    )
    return Decision(
        mode=mode,
        issue_number=issue_number,
        title=title,
        marker=marker,
        body=body,
    )


def _write_body(path: Path, body: str) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("body output must be a regular file")
    parent = path.parent.resolve(strict=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temporary = Path(temporary_name)
    try:
        with open(
            descriptor,
            "w",
            encoding="utf-8",
            newline="\n",
            closefd=True,
        ) as stream:
            stream.write(body)
            stream.flush()
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def _append_github_outputs(path: Path, decision: Decision) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("GitHub output must be a regular file")
    values: list[tuple[str, str]] = [
        ("mode", decision.mode),
        (
            "issue_number",
            "" if decision.issue_number is None else str(decision.issue_number),
        ),
        ("marker", decision.marker),
    ]
    if decision.title is not None:
        values.append(("title", decision.title))
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        for key, value in values:
            if "\n" in value or "\r" in value:
                raise ValueError(f"GitHub output {key} must be one line")
            stream.write(f"{key}={value}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--now", required=True)
    parser.add_argument("--issues-json", required=True, type=Path)
    parser.add_argument("--runs-json", required=True, type=Path)
    parser.add_argument("--releases-json", required=True, type=Path)
    parser.add_argument("--body", required=True, type=Path)
    parser.add_argument("--github-output", required=True, type=Path)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    options = _parser().parse_args(arguments)
    decision = build_decision(
        repository=options.repository,
        now=_parse_github_time(options.now, "now"),
        issues=load_issue_pages(options.issues_json),
        runs=load_run_pages(options.runs_json),
        releases=load_release_pages(options.releases_json),
    )
    _write_body(options.body, decision.body)
    _append_github_outputs(options.github_output, decision)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
