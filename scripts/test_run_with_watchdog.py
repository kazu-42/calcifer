import argparse
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import run_with_watchdog


class WatchdogBudgetTests(unittest.TestCase):
    def test_positive_float_rejects_non_finite_values(self) -> None:
        for value in ("nan", "inf", "+inf", "-inf"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(
                    argparse.ArgumentTypeError, "expected a positive finite number"
                ):
                    run_with_watchdog._positive_float(value)

    def test_budget_binds_source_internal_watchdog_and_job_margins(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary, "packaged_smoke.rs")
            source.write_text(
                "const PACKAGE_SUPERVISOR_EXTERNAL_HARD_TIMEOUT: Duration = "
                "Duration::from_secs(25 * 60);\n",
                encoding="utf-8",
            )
            budget = run_with_watchdog.validate_budget(
                rust_source=source,
                rust_constant="PACKAGE_SUPERVISOR_EXTERNAL_HARD_TIMEOUT",
                internal_fence_seconds=1_500,
                watchdog_seconds=1_680,
                watchdog_margin_seconds=180,
                job_timeout_minutes=45,
                job_margin_seconds=1_020,
            )

        self.assertEqual(budget.internal_fence_seconds, 1_500)
        self.assertEqual(budget.watchdog_seconds, 1_680)
        self.assertEqual(budget.job_timeout_seconds, 2_700)

    def test_budget_rejects_source_or_margin_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = pathlib.Path(temporary, "packaged_smoke.rs")
            source.write_text(
                "const PACKAGE_SUPERVISOR_EXTERNAL_HARD_TIMEOUT: Duration = "
                "Duration::from_secs(24 * 60);\n",
                encoding="utf-8",
            )
            arguments = {
                "rust_source": source,
                "rust_constant": "PACKAGE_SUPERVISOR_EXTERNAL_HARD_TIMEOUT",
                "internal_fence_seconds": 1_500,
                "watchdog_seconds": 1_680,
                "watchdog_margin_seconds": 180,
                "job_timeout_minutes": 45,
                "job_margin_seconds": 1_020,
            }
            with self.assertRaisesRegex(ValueError, "Rust source"):
                run_with_watchdog.validate_budget(**arguments)

            source.write_text(
                "const PACKAGE_SUPERVISOR_EXTERNAL_HARD_TIMEOUT: Duration = "
                "Duration::from_secs(25 * 60);\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "watchdog margin"):
                run_with_watchdog.validate_budget(
                    **{**arguments, "watchdog_seconds": 1_679}
                )
            with self.assertRaisesRegex(ValueError, "job margin"):
                run_with_watchdog.validate_budget(
                    **{**arguments, "job_timeout_minutes": 44}
                )


class WatchdogProcessTests(unittest.TestCase):
    def _wait_for_identity_file(
        self, path: pathlib.Path, *, timeout_seconds: float = 5.0
    ) -> tuple[int, int]:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                fields = path.read_text(encoding="utf-8").split()
            except FileNotFoundError:
                time.sleep(0.01)
                continue
            if len(fields) == 2:
                return int(fields[0]), int(fields[1])
            time.sleep(0.01)
        self.fail(f"process identity file was not ready: {path}")

    def _identity_is_live(self, pid: int, process_group: int) -> bool:
        try:
            return os.getpgid(pid) == process_group
        except ProcessLookupError:
            return False

    def _wait_for_identity_absent(
        self, pid: int, process_group: int, *, timeout_seconds: float = 5.0
    ) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if not self._identity_is_live(pid, process_group):
                return True
            time.sleep(0.01)
        return not self._identity_is_live(pid, process_group)

    def _kill_owned_process_group(self, pid: int, process_group: int) -> None:
        try:
            if os.getpgid(pid) == process_group:
                os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass

    def _exercise_watchdog_interruption(
        self, requested: signal.Signals, second: signal.Signals
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            identity_path = pathlib.Path(temporary, "watched.identity")
            watched_program = (
                "import os,pathlib,signal,time; "
                "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                "signal.signal(signal.SIGINT,signal.SIG_IGN); "
                f"pathlib.Path({str(identity_path)!r}).write_text("
                "f'{os.getpid()} {os.getpgrp()}\\n',encoding='utf-8'); "
                "deadline=time.monotonic()+5; "
                "time.sleep(max(0,deadline-time.monotonic()))"
            )
            watchdog = subprocess.Popen(
                [
                    sys.executable,
                    str(pathlib.Path(run_with_watchdog.__file__).resolve()),
                    "run",
                    "--timeout-seconds",
                    "10",
                    "--term-grace-seconds",
                    "0.5",
                    "--",
                    sys.executable,
                    "-c",
                    watched_program,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            watched_identity: tuple[int, int] | None = None
            output_collected = False
            try:
                watched_identity = self._wait_for_identity_file(identity_path)
                os.kill(watchdog.pid, requested)
                time.sleep(0.05)
                self.assertIsNone(
                    watchdog.poll(), "watchdog exited before its bounded cleanup grace"
                )
                os.kill(watchdog.pid, second)
                _, stderr = watchdog.communicate(timeout=5)
                output_collected = True

                self.assertEqual(watchdog.returncode, 128 + int(requested), stderr)
                self.assertTrue(
                    self._wait_for_identity_absent(*watched_identity),
                    "watchdog interruption left its exact command group alive",
                )
            finally:
                if watchdog.poll() is None:
                    watchdog.kill()
                    watchdog.wait(timeout=5)
                if not output_collected:
                    watchdog.communicate(timeout=5)
                if watched_identity is not None:
                    self._kill_owned_process_group(*watched_identity)
                    self.assertTrue(
                        self._wait_for_identity_absent(*watched_identity),
                        "test cleanup could not remove its owned process group",
                    )

    def test_run_rejects_non_finite_durations_before_spawn(self) -> None:
        with mock.patch.object(run_with_watchdog.subprocess, "Popen") as spawn:
            for timeout, grace in (
                (float("nan"), 1.0),
                (float("inf"), 1.0),
                (1.0, float("nan")),
                (1.0, float("inf")),
            ):
                with self.subTest(timeout=timeout, grace=grace):
                    with self.assertRaisesRegex(ValueError, "positive and finite"):
                        run_with_watchdog.run_command(
                            ["must-not-spawn"],
                            timeout_seconds=timeout,
                            term_grace_seconds=grace,
                        )
            spawn.assert_not_called()

    def test_run_returns_the_child_status_before_deadline(self) -> None:
        original_handlers = {
            requested: signal.getsignal(requested)
            for requested in (signal.SIGTERM, signal.SIGINT)
        }
        status = run_with_watchdog.run_command(
            [sys.executable, "-c", "raise SystemExit(7)"],
            timeout_seconds=5,
            term_grace_seconds=1,
        )
        self.assertEqual(status, 7)
        self.assertEqual(
            {
                requested: signal.getsignal(requested)
                for requested in (signal.SIGTERM, signal.SIGINT)
            },
            original_handlers,
        )

    @unittest.skipUnless(
        hasattr(signal, "pthread_sigmask"), "POSIX signal masks required"
    )
    def test_child_does_not_inherit_watchdog_private_signal_blocking(self) -> None:
        original_mask = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        self.assertNotIn(signal.SIGTERM, original_mask)
        self.assertNotIn(signal.SIGINT, original_mask)
        child = "\n".join(
            (
                "import signal",
                "blocked = signal.pthread_sigmask(signal.SIG_BLOCK, [])",
                "raise SystemExit(19 if "
                "signal.SIGTERM in blocked or signal.SIGINT in blocked else 0)",
            )
        )

        status = run_with_watchdog.run_command(
            [sys.executable, "-c", child],
            timeout_seconds=5,
            term_grace_seconds=1,
        )

        self.assertEqual(status, 0)
        self.assertEqual(
            signal.pthread_sigmask(signal.SIG_BLOCK, []),
            original_mask,
        )

    def test_signal_during_spawn_is_deferred_until_direct_child_is_bound(self) -> None:
        events: list[tuple[str, object]] = []

        class FakeProcess:
            pid = 42_424
            returncode: int | None = None

            def wait(self, timeout: float) -> int:
                events.append(("wait", timeout))
                self.returncode = -signal.SIGKILL
                return self.returncode

        fake_process = FakeProcess()

        def spawn(*_arguments: object, **options: object) -> FakeProcess:
            self.assertEqual(options, {"start_new_session": True})
            handler = signal.getsignal(signal.SIGTERM)
            self.assertTrue(callable(handler))
            events.append(("spawn", signal.SIGTERM))
            handler(signal.SIGTERM, None)  # type: ignore[operator]
            return fake_process

        def record_signal(process: object, requested: signal.Signals) -> None:
            self.assertIs(process, fake_process)
            events.append(("signal", requested))

        with (
            mock.patch.object(
                run_with_watchdog.subprocess,
                "Popen",
                side_effect=spawn,
            ),
            mock.patch.object(
                run_with_watchdog,
                "_signal_process_group",
                side_effect=record_signal,
            ),
            mock.patch.object(
                run_with_watchdog.time,
                "sleep",
                side_effect=lambda seconds: events.append(("sleep", seconds)),
            ),
        ):
            status = run_with_watchdog.run_command(
                ["fake"], timeout_seconds=5, term_grace_seconds=2
            )

        self.assertEqual(status, 128 + signal.SIGTERM)
        self.assertEqual(
            events,
            [
                ("spawn", signal.SIGTERM),
                ("signal", signal.SIGTERM),
                ("sleep", 2),
                ("signal", signal.SIGKILL),
                ("wait", 2),
            ],
        )

    @unittest.skipUnless(sys.platform != "win32", "process groups require POSIX")
    def test_sigterm_routes_through_bounded_cleanup_and_ignores_second_signal(
        self,
    ) -> None:
        self._exercise_watchdog_interruption(signal.SIGTERM, signal.SIGINT)

    @unittest.skipUnless(sys.platform != "win32", "process groups require POSIX")
    def test_sigint_routes_through_bounded_cleanup_and_ignores_second_signal(
        self,
    ) -> None:
        self._exercise_watchdog_interruption(signal.SIGINT, signal.SIGTERM)

    @unittest.skipUnless(sys.platform != "win32", "process groups require POSIX")
    def test_zero_exit_fails_closed_when_same_process_group_residue_remains(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            identity_path = pathlib.Path(temporary, "residue.identity")
            release_path = pathlib.Path(temporary, "residue.release")
            residue_program = "\n".join(
                (
                    "import pathlib,time",
                    f"release=pathlib.Path({str(release_path)!r})",
                    "deadline=time.monotonic()+5",
                    "while not release.exists() and time.monotonic()<deadline:",
                    "    time.sleep(0.01)",
                )
            )
            parent_program = (
                "import os,pathlib,subprocess,sys; "
                f"child=subprocess.Popen([sys.executable,'-c',{residue_program!r}]); "
                f"pathlib.Path({str(identity_path)!r}).write_text("
                "f'{child.pid} {os.getpgrp()}\\n',encoding='utf-8')"
            )
            residue_identity: tuple[int, int] | None = None
            try:
                status = run_with_watchdog.run_command(
                    [sys.executable, "-c", parent_program],
                    timeout_seconds=5,
                    term_grace_seconds=0.1,
                )
                residue_identity = self._wait_for_identity_file(identity_path)
                self.assertEqual(
                    status, run_with_watchdog.PROCESS_GROUP_RESIDUE_EXIT_CODE
                )
                self.assertTrue(self._identity_is_live(*residue_identity))
            finally:
                release_path.touch(exist_ok=True)
                if residue_identity is not None:
                    if not self._wait_for_identity_absent(*residue_identity):
                        self._kill_owned_process_group(*residue_identity)
                    self.assertTrue(
                        self._wait_for_identity_absent(*residue_identity),
                        "test cleanup could not remove its owned process group",
                    )

    @unittest.skipUnless(sys.platform != "win32", "process groups require POSIX")
    def test_run_times_out_and_returns_124_after_bounded_group_signals(self) -> None:
        started = time.monotonic()
        status = run_with_watchdog.run_command(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            timeout_seconds=0.1,
            term_grace_seconds=0.1,
        )
        elapsed = time.monotonic() - started
        self.assertEqual(status, run_with_watchdog.TIMEOUT_EXIT_CODE)
        self.assertLess(elapsed, 5)

    @unittest.skipUnless(sys.platform != "win32", "sessions require POSIX")
    def test_new_session_descendant_escapes_the_command_group_watchdog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            pid_path = pathlib.Path(temporary, "escaped.pid")
            escaped = (
                "import os,time; "
                "os.setsid(); "
                f"handle=open({str(pid_path)!r},'w',encoding='utf-8'); "
                "handle.write(str(os.getpid())); handle.flush(); "
                "os.fsync(handle.fileno()); "
                "handle.close(); time.sleep(60)"
            )
            parent = (
                "import subprocess,sys,time; "
                f"subprocess.Popen([sys.executable,'-c',{escaped!r}]); "
                "time.sleep(60)"
            )
            escaped_pid = None
            try:
                status = run_with_watchdog.run_command(
                    [sys.executable, "-c", parent],
                    timeout_seconds=1,
                    term_grace_seconds=0.1,
                )
                self.assertEqual(status, run_with_watchdog.TIMEOUT_EXIT_CODE)
                escaped_pid = int(pid_path.read_text(encoding="utf-8"))
                os.kill(escaped_pid, 0)
            finally:
                if escaped_pid is not None:
                    try:
                        os.kill(escaped_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

    @unittest.skipUnless(sys.platform != "win32", "process groups require POSIX")
    def test_timeout_keeps_leader_unreaped_until_both_group_signals(self) -> None:
        events: list[tuple[str, object]] = []

        class FakeProcess:
            pid = 42_424

            def __init__(self) -> None:
                self.wait_count = 0

            def wait(self, timeout: float) -> int:
                self.wait_count += 1
                events.append(("wait", timeout))
                if self.wait_count == 1:
                    raise subprocess.TimeoutExpired(["fake"], timeout)
                return -signal.SIGKILL

        fake_process = FakeProcess()

        def record_signal(process: object, requested: signal.Signals) -> None:
            self.assertIs(process, fake_process)
            events.append(("signal", requested))

        with (
            mock.patch.object(
                run_with_watchdog.subprocess,
                "Popen",
                return_value=fake_process,
            ),
            mock.patch.object(
                run_with_watchdog,
                "_signal_process_group",
                side_effect=record_signal,
            ),
            mock.patch.object(
                run_with_watchdog.time,
                "sleep",
                side_effect=lambda seconds: events.append(("sleep", seconds)),
            ),
        ):
            status = run_with_watchdog.run_command(
                ["fake"], timeout_seconds=5, term_grace_seconds=2
            )

        self.assertEqual(status, run_with_watchdog.TIMEOUT_EXIT_CODE)
        self.assertEqual(
            events,
            [
                ("wait", 5),
                ("signal", signal.SIGTERM),
                ("sleep", 2),
                ("signal", signal.SIGKILL),
                ("wait", 2),
            ],
        )

    @unittest.skipUnless(sys.platform != "win32", "process groups require POSIX")
    def test_term_ignoring_direct_command_is_reaped_after_fixed_grace(self) -> None:
        command = (
            "import signal,time; "
            "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "time.sleep(60)"
        )
        started = time.monotonic()
        status = run_with_watchdog.run_command(
            [sys.executable, "-c", command],
            timeout_seconds=0.5,
            term_grace_seconds=0.2,
        )
        elapsed = time.monotonic() - started

        self.assertEqual(status, run_with_watchdog.TIMEOUT_EXIT_CODE)
        self.assertGreaterEqual(elapsed, 0.7)
        self.assertLess(elapsed, 5)


class WatchdogWorkflowTests(unittest.TestCase):
    def _workflow(self) -> str:
        repository = pathlib.Path(__file__).resolve().parent.parent
        return (repository / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    def test_all_six_package_tests_keep_exact_discovery_and_execution(self) -> None:
        workflow = self._workflow()
        contract_step = workflow.split(
            "      - name: Run pinned Codex contract probes\n", 1
        )[1].split(
            "      - name: Build and verify the package TUI launcher fixture\n", 1
        )[0]
        contract_tests = (
            "providers::codex::handoff_compat::tests::"
            "packaged_codex_0_144_4_passes_the_complete_handoff_probe",
            "providers::codex::supervisor::packaged_smoke::"
            "packaged_codex_running_turn_obeys_the_pinned_graceful_drain_contract",
            "providers::codex::supervisor::packaged_smoke::"
            "packaged_codex_detached_tool_inherits_no_calcifer_authority",
            "providers::codex::supervisor::packaged_smoke::"
            "packaged_codex_typed_monitor_accepts_usage_and_redacts_provider_failure",
        )
        for test_name in contract_tests:
            self.assertEqual(workflow.count(test_name), 1)
            self.assertIn(test_name, contract_step)
        self.assertEqual(contract_step.count("--exact"), 2)
        self.assertEqual(contract_step.count("--ignored"), 2)

        prepare_tui_step = workflow.split(
            "      - name: Prepare the exact official Codex TUI libtest\n", 1
        )[1].split(
            "      - name: Run official Codex TUI native functional probe\n", 1
        )[0]
        normal_tui_test = (
            "providers::codex::supervisor::packaged_smoke::"
            "packaged_codex_official_tui_uses_production_coordinator_guardian_"
            "session_pty_and_job_control"
        )
        recovery_tui_test = (
            "providers::codex::supervisor::packaged_smoke::"
            "packaged_codex_official_tui_recovers_retained_cleanup_pending_"
            "with_four_proofs"
        )
        self.assertEqual(workflow.count(normal_tui_test), 1)
        self.assertEqual(workflow.count(recovery_tui_test), 1)
        self.assertIn(
            'case "${PACKAGE_OFFICIAL_TUI_SCENARIO:?}" in', prepare_tui_step
        )
        self.assertIn("normal)", prepare_tui_step)
        self.assertIn("recovery)", prepare_tui_step)
        self.assertNotIn("for test_name", prepare_tui_step)
        self.assertIn("--no-run", prepare_tui_step)
        self.assertIn("--message-format=json", prepare_tui_step)
        self.assertIn("CALCIFER_PACKAGE_TUI_TEST_BINARY", prepare_tui_step)
        self.assertIn("CALCIFER_PACKAGE_TUI_TEST_NAME", prepare_tui_step)
        self.assertEqual(prepare_tui_step.count("--exact"), 1)
        self.assertEqual(prepare_tui_step.count("--ignored"), 1)
        first_metadata_create = prepare_tui_step.index(
            'artifact_json="$(mktemp '
        )
        metadata_cleanup_trap = prepare_tui_step.index(
            "trap cleanup_metadata EXIT"
        )
        self.assertLess(metadata_cleanup_trap, first_metadata_create)

    def test_launcher_is_staged_as_a_private_single_link_copy_before_export(
        self,
    ) -> None:
        workflow = self._workflow()
        launcher_step = workflow.split(
            "      - name: Build and verify the package TUI launcher fixture\n", 1
        )[1].split(
            "      - name: Prepare the exact official Codex TUI libtest\n", 1
        )[0]

        build = launcher_step.index("cargo +1.96.0 build")
        stage_directory = launcher_step.index(
            'launcher_directory="${CALCIFER_CODEX_PACKAGE_ROOT:?}/launcher"'
        )
        copy = launcher_step.index(
            '(umask 077; cp "${built_fixture}" "${fixture_binary}")'
        )
        compare = launcher_step.index(
            'if ! cmp -s "${built_fixture}" "${fixture_binary}"; then'
        )
        single_link = launcher_step.index(
            'if [[ "${launcher_link_count}" != 1 ]]; then'
        )
        export = launcher_step.index(
            'CALCIFER_PACKAGE_TUI_LAUNCHER=${fixture_binary}'
        )

        self.assertLess(build, stage_directory)
        self.assertLess(stage_directory, copy)
        self.assertLess(copy, compare)
        self.assertLess(compare, single_link)
        self.assertLess(single_link, export)
        self.assertIn('mkdir -m 0700 "${launcher_directory}"', launcher_step)
        self.assertIn('chmod 0700 "${fixture_binary}"', launcher_step)
        self.assertIn('! -O "${fixture_binary}"', launcher_step)
        self.assertNotIn(
            'CALCIFER_PACKAGE_TUI_LAUNCHER=${built_fixture}', launcher_step
        )

    def test_linux_official_tui_is_fail_closed_inside_loopback_only_netns(
        self,
    ) -> None:
        workflow = self._workflow()
        linux_step_name = (
            "      - name: Run official Codex TUI in a loopback-only "
            "network namespace\n"
        )
        native_step = workflow.split(
            "      - name: Run official Codex TUI native functional probe\n", 1
        )[1].split(linux_step_name, 1)[0]
        linux_step = workflow.split(linux_step_name, 1)[1].split(
            "      # The watchdog bounds only", 1
        )[0]

        self.assertIn(
            "if: matrix.suite == 'official-tui' && runner.os != 'Linux'",
            native_step,
        )
        self.assertIn("scripts/run_with_watchdog.py run", native_step)
        self.assertIn('"${CALCIFER_PACKAGE_TUI_TEST_BINARY:?}"', native_step)
        self.assertNotIn("cargo ", native_step)

        self.assertIn(
            "if: matrix.suite == 'official-tui' && runner.os == 'Linux'",
            linux_step,
        )
        for command in ("sudo", "unshare", "setpriv", "ip"):
            self.assertIn(f"command -v {command}", linux_step)
        self.assertIn("sudo -n true", linux_step)
        self.assertIn("scripts/run_with_watchdog.py run", linux_step)
        self.assertIn("scripts/run_loopback_netns.py", linux_step)
        self.assertIn(
            '--test-binary "${CALCIFER_PACKAGE_TUI_TEST_BINARY:?}"', linux_step
        )
        self.assertIn(
            '--test-name "${CALCIFER_PACKAGE_TUI_TEST_NAME:?}"', linux_step
        )
        self.assertIn(
            '--codex-binary "${CALCIFER_CODEX_COMPAT_BINARY:?}"', linux_step
        )
        self.assertIn(
            '--launcher-binary "${CALCIFER_PACKAGE_TUI_LAUNCHER:?}"',
            linux_step,
        )
        self.assertNotIn("cargo ", linux_step)
        self.assertNotIn("runner.os != 'Linux'", linux_step)

    def test_official_tui_scenarios_are_independent_45_minute_matrix_jobs(
        self,
    ) -> None:
        workflow = self._workflow()
        matrix = workflow.split("  pinned-codex-package:\n", 1)[1].split(
            "    runs-on:", 1
        )[0]
        self.assertIn(
            "name: Pinned Codex (${{ matrix.scenario }}, ${{ matrix.os }})", matrix
        )
        self.assertEqual(matrix.count("suite: official-tui"), 4)
        self.assertEqual(matrix.count("scenario: official-tui-normal"), 2)
        self.assertEqual(matrix.count("scenario: official-tui-recovery"), 2)
        self.assertEqual(matrix.count("job_timeout_minutes: 45"), 4)
        self.assertEqual(matrix.count("os: ubuntu-24.04"), 3)
        self.assertNotIn("os: ubuntu-latest", matrix)

        normal_entries = (
            "- os: ubuntu-24.04\n"
            "            suite: official-tui\n"
            "            scenario: official-tui-normal\n"
            "            job_timeout_minutes: 45",
            "- os: macos-latest\n"
            "            suite: official-tui\n"
            "            scenario: official-tui-normal\n"
            "            job_timeout_minutes: 45",
        )
        recovery_entries = (
            "- os: ubuntu-24.04\n"
            "            suite: official-tui\n"
            "            scenario: official-tui-recovery\n"
            "            job_timeout_minutes: 45",
            "- os: macos-latest\n"
            "            suite: official-tui\n"
            "            scenario: official-tui-recovery\n"
            "            job_timeout_minutes: 45",
        )
        for entry in normal_entries + recovery_entries:
            self.assertIn(entry, matrix)

    def test_pinned_codex_matrix_has_one_stable_required_check_gate(self) -> None:
        workflow = self._workflow()
        gate = workflow.split("  pinned-codex-gate:\n", 1)[1].split(
            "  msrv:\n", 1
        )[0]
        self.assertIn("name: Pinned Codex Package", gate)
        self.assertIn("if: always()", gate)
        self.assertIn("needs: pinned-codex-package", gate)
        self.assertIn(
            "PINNED_CODEX_RESULT: ${{ needs.pinned-codex-package.result }}", gate
        )
        self.assertIn('if [[ "${PINNED_CODEX_RESULT:?}" != success ]]; then', gate)
        self.assertNotIn("actions/checkout", gate)

    def test_prepare_registers_and_guards_scratch_before_fallible_package_io(
        self,
    ) -> None:
        workflow = self._workflow()
        prepare_step = workflow.split(
            "      - name: Prepare checksum-pinned Codex package\n", 1
        )[1].split("      - name: Run pinned Codex contract probes\n", 1)[0]
        created = prepare_step.index('scratch="$(mktemp -d')
        guarded = prepare_step.index("trap cleanup_prepare_failure EXIT")
        registered = prepare_step.index("CALCIFER_CODEX_PACKAGE_ROOT=${scratch}")
        download = prepare_step.index("curl \\")
        retained = prepare_step.index("retain_scratch=true")
        self.assertLess(created, guarded)
        self.assertLess(guarded, registered)
        self.assertLess(registered, download)
        self.assertLess(download, retained)

    def test_failed_watchdog_retains_scratch_for_ephemeral_runner_teardown(
        self,
    ) -> None:
        workflow = self._workflow()
        cleanup_contract = (
            "      - name: Remove pinned Codex package scratch "
            "after successful probes\n"
            "        if: success()\n"
        )
        self.assertIn(cleanup_contract, workflow)
        self.assertNotIn(
            "      - name: Remove pinned Codex package scratch\n        if: always()\n",
            workflow,
        )
        self.assertIn(
            'if [[ -e "${package_root}" || -L "${package_root}" ]]; then',
            workflow,
        )
        self.assertIn(
            'if [[ -z "${package_root}" ]]; then\n'
            '            echo "Pinned Codex package scratch was not registered." >&2\n'
            "            exit 1",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
