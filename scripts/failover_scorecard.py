#!/usr/bin/env python3
"""Run the guarded-failover matrix through the packaged public Calcifer CLI."""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
import time
from collections.abc import Mapping, Sequence
from pathlib import Path


CASE_FIELDS = frozenset(
    {
        "scenario",
        "outcome_code",
        "source_alias",
        "target_alias",
        "generation_count",
        "provider_start_count",
        "recovery_result",
        "duration_bucket",
    }
)
RUST_CASE_FIELDS = CASE_FIELDS - {"duration_bucket"}
DURATION_BUCKETS = ("lt_250_ms", "lt_1_s", "lt_5_s", "gte_5_s")
FIXED_ALIASES = frozenset({"source", "target"})
FIXED_RECOVERY_RESULTS = frozenset(
    {"none", "source_recovered", "target_recovered"}
)
CANONICAL_CODE = re.compile(r"^[a-z][a-z0-9_]{0,95}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
THREAD_ID = "01900000-0000-7000-8000-000000000129"

# Insertion order is the schema-v1 execution and artifact order.
EXPECTED_CASES: dict[str, dict[str, object]] = {
    "available_continuation": {
        "outcome_code": "continued",
        "generation_count": 2,
        "provider_start_count": 2,
        "recovery_result": "none",
    },
    "rounded_100_without_reached_type": {
        "outcome_code": "codex_exhaustion_revalidation_failed",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "stale_usage": {
        "outcome_code": "codex_exhaustion_revalidation_failed",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "unknown_usage": {
        "outcome_code": "codex_exhaustion_revalidation_failed",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "authentication_failure": {
        "outcome_code": "codex_exhaustion_revalidation_failed",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "provider_timeout": {
        "outcome_code": "codex_exhaustion_revalidation_failed",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "network_error": {
        "outcome_code": "codex_exhaustion_revalidation_failed",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "provider_overload": {
        "outcome_code": "codex_exhaustion_revalidation_failed",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "malformed_protocol": {
        "outcome_code": "codex_handoff_protocol_invalid",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "natural_exit_75": {
        "outcome_code": "codex_exhaustion_revalidation_failed",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "pool_exhausted": {
        "outcome_code": "codex_failover_pool_exhausted",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "pool_all_unknown": {
        "outcome_code": "codex_failover_pool_unknown",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "pool_busy": {
        "outcome_code": "codex_failover_pool_busy",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "pool_no_eligible": {
        "outcome_code": "codex_failover_pool_no_eligible_profile",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "membership_change": {
        "outcome_code": "codex_failover_selection_failed",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "policy_change": {
        "outcome_code": "routing_pool_disabled",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "source_crash_recovery": {
        "outcome_code": "continued",
        "generation_count": 2,
        "provider_start_count": 2,
        "recovery_result": "source_recovered",
    },
    "target_crash_recovery": {
        "outcome_code": "continued",
        "generation_count": 2,
        "provider_start_count": 2,
        "recovery_result": "target_recovered",
    },
    "target_contention": {
        "outcome_code": "codex_failover_pool_busy",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
    "cooldown_exhaustion": {
        "outcome_code": "codex_failover_pool_no_eligible_profile",
        "generation_count": 1,
        "provider_start_count": 1,
        "recovery_result": "none",
    },
}


def duration_bucket(elapsed_seconds: float) -> str:
    if elapsed_seconds < 0 or not math.isfinite(elapsed_seconds):
        raise ValueError("duration must be finite and non-negative")
    if elapsed_seconds < 0.250:
        return "lt_250_ms"
    if elapsed_seconds < 1:
        return "lt_1_s"
    if elapsed_seconds < 5:
        return "lt_5_s"
    return "gte_5_s"


def validate_case(case: Mapping[str, object]) -> None:
    if set(case) != CASE_FIELDS:
        raise ValueError("case does not match the schema allowlist")
    scenario = case["scenario"]
    if not isinstance(scenario, str) or scenario not in EXPECTED_CASES:
        raise ValueError("scenario is not a fixed schema-v1 case")
    outcome = case["outcome_code"]
    if (
        not isinstance(outcome, str)
        or CANONICAL_CODE.fullmatch(outcome) is None
        or outcome
        not in {expected["outcome_code"] for expected in EXPECTED_CASES.values()}
    ):
        raise ValueError("outcome_code is not a fixed outcome")
    source = case["source_alias"]
    target = case["target_alias"]
    if source not in FIXED_ALIASES or target not in FIXED_ALIASES | {None}:
        raise ValueError("case contains a non-fixed local alias")
    for field in ("generation_count", "provider_start_count"):
        value = case[field]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 8:
            raise ValueError(f"{field} is outside its fixed bound")
    if case["recovery_result"] not in FIXED_RECOVERY_RESULTS:
        raise ValueError("recovery_result is not fixed")
    if case["duration_bucket"] not in DURATION_BUCKETS:
        raise ValueError("duration_bucket is not fixed")


def validate_expected_result(case: Mapping[str, object]) -> None:
    validate_case(case)
    expected = EXPECTED_CASES[str(case["scenario"])]
    for field, value in expected.items():
        if case[field] != value:
            raise ValueError(
                f"{case['scenario']} disagreed on {field}: "
                f"expected {value!r}, found {case[field]!r}"
            )
    expected_target = "target" if expected["generation_count"] == 2 else None
    if case["target_alias"] != expected_target:
        raise ValueError(f"{case['scenario']} disagreed on target_alias")


def _p95_bucket(cases: Sequence[Mapping[str, object]]) -> str:
    ranks = {name: index for index, name in enumerate(DURATION_BUCKETS)}
    ordered = sorted(
        (str(case["duration_bucket"]) for case in cases), key=ranks.__getitem__
    )
    index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return ordered[index]


def write_scorecard(
    output: Path,
    *,
    source_commit: str,
    cases: Sequence[Mapping[str, object]],
    controlled_regression_detected: bool,
) -> None:
    if COMMIT.fullmatch(source_commit) is None:
        raise ValueError("source commit must be a lowercase full Git digest")
    if [case.get("scenario") for case in cases] != list(EXPECTED_CASES):
        raise ValueError("scorecard scenarios are missing, duplicated, or reordered")
    for case in cases:
        validate_expected_result(case)
    if not controlled_regression_detected:
        raise ValueError("controlled integration regression was not detected")
    p95 = _p95_bucket(cases)
    if DURATION_BUCKETS.index(p95) > DURATION_BUCKETS.index("lt_5_s"):
        raise ValueError("scorecard p95 exceeded the documented five-second budget")
    document = {
        "schema_version": 1,
        "source_commit": source_commit,
        "scenario_count": len(cases),
        "expected_outcome_agreement_percent": 100,
        "unexpected_provider_starts": 0,
        "p95_duration_bucket": p95,
        "controlled_regression_detected": True,
        "cases": list(cases),
    }
    encoded = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        output.unlink(missing_ok=True)
        raise


def _run(command: Sequence[str], *, environment: Mapping[str, str], cwd: Path) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=dict(environment),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"setup command failed with exit code {completed.returncode}")


def _prepare_fixture(
    root: Path, calcifer: Path, fixture_codex: Path
) -> tuple[dict[str, str], Path]:
    bin_directory = root / "bin"
    workspace = root / "workspace"
    state = root / "state"
    bin_directory.mkdir(mode=0o700)
    workspace.mkdir(mode=0o700)
    (workspace / ".git").mkdir(mode=0o700)
    codex = bin_directory / "codex"
    shutil.copyfile(fixture_codex, codex)
    codex.chmod(0o700)
    environment = {
        "PATH": os.pathsep.join((str(bin_directory), "/usr/bin", "/bin")),
        "CALCIFER_HOME": str(state),
        "HOME": str(root / "environment-home"),
        "TERM": "xterm-256color",
    }
    Path(environment["HOME"]).mkdir(mode=0o700)
    for alias in ("source", "target", "reserve"):
        _run(
            (str(calcifer), "auth", "add", "codex", alias),
            environment=environment,
            cwd=workspace,
        )
    _run(
        (
            str(calcifer),
            "routing",
            "domain",
            "create",
            "codex",
            "scorecard-domain",
            "codex@source",
            "codex@target",
            "codex@reserve",
        ),
        environment=environment,
        cwd=workspace,
    )
    _run(
        (
            str(calcifer),
            "routing",
            "pool",
            "create",
            "codex@scorecard-domain",
            "scorecard-pool",
            "codex@source",
            "codex@target",
            "codex@reserve",
        ),
        environment=environment,
        cwd=workspace,
    )
    _run(
        (
            str(calcifer),
            "routing",
            "pool",
            "enable",
            "codex@scorecard-pool",
        ),
        environment=environment,
        cwd=workspace,
    )
    return environment, workspace


def _run_case(
    *,
    calcifer: Path,
    environment: Mapping[str, str],
    workspace: Path,
    report: Path,
    scenario: str,
    inject_regression: bool = False,
) -> dict[str, object]:
    case_environment = dict(environment)
    case_environment.update(
        {
            "CALCIFER_FAILOVER_SCORECARD_MODE": "v1",
            "CALCIFER_FAILOVER_SCORECARD_SCENARIO": scenario,
            "CALCIFER_FAILOVER_SCORECARD_REPORT": str(report),
        }
    )
    if inject_regression:
        case_environment["CALCIFER_FAILOVER_SCORECARD_INJECT"] = (
            "unexpected_target_start"
        )
    started = time.monotonic()
    completed = subprocess.run(
        (
            str(calcifer),
            "resume",
            "--experimental-supervised",
            "--failover-pool",
            "codex@scorecard-pool",
            "codex@source",
            THREAD_ID,
        ),
        cwd=workspace,
        env=case_environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=15,
        check=False,
    )
    elapsed = time.monotonic() - started
    expected_exit = 0 if EXPECTED_CASES[scenario]["outcome_code"] == "continued" else 1
    if completed.returncode != expected_exit:
        raise RuntimeError(
            f"{scenario} public command exited {completed.returncode}, "
            f"expected {expected_exit}"
        )
    try:
        raw = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{scenario} did not produce a valid fixture report") from error
    if not isinstance(raw, dict) or set(raw) != RUST_CASE_FIELDS:
        raise ValueError(f"{scenario} fixture report violated its field allowlist")
    case = {**raw, "duration_bucket": duration_bucket(elapsed)}
    validate_case(case)
    return case


def run_scorecard(
    *, calcifer: Path, fixture_codex: Path, output: Path, source_commit: str
) -> None:
    calcifer = calcifer.resolve(strict=True)
    fixture_codex = fixture_codex.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="calcifer-failover-scorecard-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        environment, workspace = _prepare_fixture(root, calcifer, fixture_codex)

        regression = _run_case(
            calcifer=calcifer,
            environment=environment,
            workspace=workspace,
            report=root / "controlled-regression.json",
            scenario="stale_usage",
            inject_regression=True,
        )
        try:
            validate_expected_result(regression)
        except ValueError:
            controlled_regression_detected = True
        else:
            controlled_regression_detected = False

        cases = []
        for index, scenario in enumerate(EXPECTED_CASES):
            case = _run_case(
                calcifer=calcifer,
                environment=environment,
                workspace=workspace,
                report=root / f"case-{index:02d}.json",
                scenario=scenario,
            )
            validate_expected_result(case)
            cases.append(case)

    write_scorecard(
        output,
        source_commit=source_commit,
        cases=cases,
        controlled_regression_detected=controlled_regression_detected,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--calcifer", type=Path, required=True)
    parser.add_argument("--fixture-codex", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    arguments = parser.parse_args()
    try:
        run_scorecard(
            calcifer=arguments.calcifer,
            fixture_codex=arguments.fixture_codex,
            output=arguments.output,
            source_commit=arguments.source_commit,
        )
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
