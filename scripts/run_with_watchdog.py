#!/usr/bin/env python3
"""Bound one POSIX command group and validate the package CI time budgets.

Descendants may deliberately create other sessions or process groups. They are
outside this helper's authority and remain the ephemeral runner's responsibility
after a watchdog failure. A normally-exited command group is observation-checked
for same-group residue, but escaped sessions remain outside that proof.
"""

from __future__ import annotations

import argparse
import ast
import dataclasses
import math
import os
import pathlib
import re
import signal
import subprocess
import sys
import time
from collections.abc import Sequence


TIMEOUT_EXIT_CODE = 124
PROCESS_GROUP_RESIDUE_EXIT_CODE = 125
MAX_RUST_SOURCE_BYTES = 1024 * 1024


@dataclasses.dataclass(frozen=True)
class WatchdogBudget:
    internal_fence_seconds: int
    watchdog_seconds: int
    job_timeout_seconds: int


class _WatchdogInterrupted(BaseException):
    def __init__(self, requested: signal.Signals) -> None:
        super().__init__(requested.name)
        self.requested = requested


class _WatchdogSignalScope:
    """Route the first interruption into cleanup and ignore later ones."""

    _watched = (signal.SIGTERM, signal.SIGINT)

    def __init__(self) -> None:
        self._previous_handlers: dict[signal.Signals, object] = {}
        self._process: subprocess.Popen[bytes] | None = None
        self._first_interruption: signal.Signals | None = None
        self._cleanup_started = False
        self._active = False

    def __enter__(self) -> _WatchdogSignalScope:
        try:
            for requested in self._watched:
                self._previous_handlers[requested] = signal.signal(
                    requested, self._handle
                )
        except BaseException:
            self._restore_handlers()
            raise
        return self

    def bind(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process

    def activate(self) -> None:
        if self._process is None:
            raise RuntimeError("watchdog signal scope has no bound process")
        # A handler may have recorded an interruption while Popen was inside
        # its critical section. Activate only after binding the exact direct
        # child, then raise synchronously so cleanup cannot lose that child.
        self._active = True
        if self._first_interruption is not None:
            raise _WatchdogInterrupted(self._first_interruption)

    def begin_cleanup(self) -> None:
        self._cleanup_started = True
        self._active = False

    def _handle(self, signum: int, _frame: object) -> None:
        requested = signal.Signals(signum)
        if (
            self._cleanup_started
            or self._first_interruption is not None
            or (
                self._process is not None
                and getattr(self._process, "returncode", None) is not None
            )
        ):
            return
        self._first_interruption = requested
        if self._active:
            raise _WatchdogInterrupted(requested)

    def _restore_handlers(self) -> None:
        for requested, previous in self._previous_handlers.items():
            signal.signal(requested, previous)
        self._previous_handlers.clear()

    def __exit__(
        self, _error_type: object, _error: object, _traceback: object
    ) -> None:
        self._restore_handlers()


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("expected a positive integer")
    return parsed


def _positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("expected a positive finite number")
    return parsed


def _evaluate_duration_expression(expression: str) -> int:
    def evaluate(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            if node.value < 0:
                raise ValueError("Rust duration expression was negative")
            return node.value
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mult)):
            left = evaluate(node.left)
            right = evaluate(node.right)
            return left + right if isinstance(node.op, ast.Add) else left * right
        raise ValueError("Rust duration expression was not a fixed integer sum/product")

    try:
        parsed = ast.parse(expression.replace("_", ""), mode="eval")
    except SyntaxError as error:
        raise ValueError("Rust duration expression was invalid") from error
    return evaluate(parsed)


def read_rust_duration_seconds(source: pathlib.Path, constant: str) -> int:
    if not re.fullmatch(r"[A-Z][A-Z0-9_]*", constant):
        raise ValueError("Rust duration constant name was invalid")
    try:
        metadata = source.stat()
    except OSError as error:
        raise ValueError("Rust source could not be inspected") from error
    if not source.is_file() or metadata.st_size > MAX_RUST_SOURCE_BYTES:
        raise ValueError("Rust source was missing, non-regular, or oversized")
    try:
        text = source.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ValueError("Rust source could not be read as UTF-8") from error
    pattern = re.compile(
        rf"^\s*const\s+{re.escape(constant)}\s*:\s*Duration\s*=\s*"
        rf"Duration::from_secs\((?P<expression>[0-9_+* ()]+)\);\s*$",
        re.MULTILINE,
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise ValueError(
            "Rust source did not contain exactly one fixed duration constant"
        )
    return _evaluate_duration_expression(matches[0].group("expression"))


def validate_budget(
    *,
    rust_source: pathlib.Path,
    rust_constant: str,
    internal_fence_seconds: int,
    watchdog_seconds: int,
    watchdog_margin_seconds: int,
    job_timeout_minutes: int,
    job_margin_seconds: int,
) -> WatchdogBudget:
    values = (
        internal_fence_seconds,
        watchdog_seconds,
        watchdog_margin_seconds,
        job_timeout_minutes,
        job_margin_seconds,
    )
    if any(type(value) is not int or value <= 0 for value in values):
        raise ValueError("watchdog budget values must be positive integers")
    source_fence = read_rust_duration_seconds(rust_source, rust_constant)
    if source_fence != internal_fence_seconds:
        raise ValueError("Rust source internal fence did not match the CI budget")
    if watchdog_seconds != internal_fence_seconds + watchdog_margin_seconds:
        raise ValueError("watchdog margin did not match the fixed CI budget")
    job_timeout_seconds = job_timeout_minutes * 60
    if job_timeout_seconds != watchdog_seconds + job_margin_seconds:
        raise ValueError("job margin did not match the fixed CI budget")
    return WatchdogBudget(
        internal_fence_seconds=internal_fence_seconds,
        watchdog_seconds=watchdog_seconds,
        job_timeout_seconds=job_timeout_seconds,
    )


def _signal_process_group(
    process: subprocess.Popen[bytes], requested: signal.Signals
) -> None:
    try:
        os.killpg(process.pid, requested)
    except ProcessLookupError:
        pass
    except PermissionError:
        # macOS can report EPERM when the leader is already a zombie and no
        # signalable member remains. A still-live direct child that was not
        # signaled will fail the bounded wait below, so this is not treated as
        # proof that cleanup succeeded.
        print(
            f"watchdog could not send {requested.name} to the command group; "
            "the bounded direct-child wait remains authoritative",
            file=sys.stderr,
            flush=True,
        )


def _terminate_and_reap_command_group(
    process: subprocess.Popen[bytes], *, term_grace_seconds: float
) -> None:
    if getattr(process, "returncode", None) is not None:
        raise RuntimeError(
            "watchdog refused to signal a command group after reaping its leader"
        )
    # Keep the leader unreaped through both group signals. Its occupied PID
    # pins the numeric PGID and prevents signal-after-reap reuse.
    _signal_process_group(process, signal.SIGTERM)
    time.sleep(term_grace_seconds)
    _signal_process_group(process, signal.SIGKILL)
    try:
        process.wait(timeout=max(term_grace_seconds, 1.0))
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            "watchdog could not reap its direct command after one-shot SIGKILL; "
            "runner teardown is required"
        ) from error


def _same_process_group_residue_exists(process_group: int) -> bool:
    try:
        # Signal zero is observation-only. Never send a terminating signal after
        # the direct child has been reaped and released its PID.
        os.killpg(process_group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # An ambiguous identity/permission result cannot prove absence.
        return True
    return True


def run_command(
    command: Sequence[str], *, timeout_seconds: float, term_grace_seconds: float
) -> int:
    if os.name != "posix":
        raise RuntimeError("the process-group watchdog requires POSIX")
    if not command:
        raise ValueError("watchdog command was empty")
    if (
        not math.isfinite(timeout_seconds)
        or not math.isfinite(term_grace_seconds)
        or timeout_seconds <= 0
        or term_grace_seconds <= 0
    ):
        raise ValueError("watchdog durations must be positive and finite")
    with _WatchdogSignalScope() as interruptions:
        process = subprocess.Popen(list(command), start_new_session=True)
        process_group = process.pid
        interruptions.bind(process)
        try:
            interruptions.activate()
            status = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            interruptions.begin_cleanup()
            print(
                f"watchdog exceeded {timeout_seconds:g}s; "
                "terminating the command process group",
                file=sys.stderr,
                flush=True,
            )
            _terminate_and_reap_command_group(
                process, term_grace_seconds=term_grace_seconds
            )
            return TIMEOUT_EXIT_CODE
        except _WatchdogInterrupted as interruption:
            interruptions.begin_cleanup()
            print(
                f"watchdog received {interruption.requested.name}; "
                "terminating the command process group",
                file=sys.stderr,
                flush=True,
            )
            _terminate_and_reap_command_group(
                process, term_grace_seconds=term_grace_seconds
            )
            return 128 + int(interruption.requested)

        if _same_process_group_residue_exists(process_group):
            print(
                "watchdog command leader exited but same-group residue remained; "
                "runner teardown is required",
                file=sys.stderr,
                flush=True,
            )
            return PROCESS_GROUP_RESIDUE_EXIT_CODE
        return status


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    budget = subparsers.add_parser("validate-budget")
    budget.add_argument("--rust-source", required=True, type=pathlib.Path)
    budget.add_argument("--rust-constant", required=True)
    budget.add_argument("--internal-fence-seconds", required=True, type=_positive_int)
    budget.add_argument("--watchdog-seconds", required=True, type=_positive_int)
    budget.add_argument("--watchdog-margin-seconds", required=True, type=_positive_int)
    budget.add_argument("--job-timeout-minutes", required=True, type=_positive_int)
    budget.add_argument("--job-margin-seconds", required=True, type=_positive_int)

    run = subparsers.add_parser("run")
    run.add_argument("--timeout-seconds", required=True, type=_positive_float)
    run.add_argument("--term-grace-seconds", required=True, type=_positive_float)
    run.add_argument("command", nargs=argparse.REMAINDER)
    return parser


def main(arguments: Sequence[str] | None = None) -> int:
    parser = _parser()
    parsed = parser.parse_args(arguments)
    if parsed.action == "validate-budget":
        validate_budget(
            rust_source=parsed.rust_source,
            rust_constant=parsed.rust_constant,
            internal_fence_seconds=parsed.internal_fence_seconds,
            watchdog_seconds=parsed.watchdog_seconds,
            watchdog_margin_seconds=parsed.watchdog_margin_seconds,
            job_timeout_minutes=parsed.job_timeout_minutes,
            job_margin_seconds=parsed.job_margin_seconds,
        )
        return 0

    command = parsed.command
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("run requires a command after --")
    status = run_command(
        command,
        timeout_seconds=parsed.timeout_seconds,
        term_grace_seconds=parsed.term_grace_seconds,
    )
    return 128 - status if status < 0 else status


if __name__ == "__main__":
    raise SystemExit(main())
