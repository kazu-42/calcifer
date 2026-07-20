import os
import pathlib
import stat
import tempfile
import unittest
from unittest import mock

import run_loopback_netns


class ArtifactValidationTests(unittest.TestCase):
    def _executable(self, directory: pathlib.Path, name: str) -> pathlib.Path:
        path = directory / name
        path.write_bytes(b"fixture")
        path.chmod(0o700)
        return path.resolve(strict=True)

    def test_artifact_identity_is_canonical_owned_regular_and_stable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = self._executable(pathlib.Path(temporary), "fixture")
            identity = run_loopback_netns.inspect_runner_artifact(
                str(binary), runner_uid=os.getuid(), label="fixture"
            )

            self.assertEqual(identity.path, str(binary))
            self.assertEqual(
                run_loopback_netns.ArtifactIdentity.decode(identity.encode()), identity
            )
            run_loopback_netns.verify_runner_artifact(
                identity, runner_uid=os.getuid(), label="fixture"
            )

    def test_artifact_rejects_relative_symlink_and_group_writable_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            binary = self._executable(root, "fixture")
            symlink = root / "fixture-link"
            symlink.symlink_to(binary)

            with self.assertRaisesRegex(ValueError, "absolute canonical"):
                run_loopback_netns.inspect_runner_artifact(
                    "fixture", runner_uid=os.getuid(), label="fixture"
                )
            with self.assertRaisesRegex(ValueError, "absolute canonical"):
                run_loopback_netns.inspect_runner_artifact(
                    str(symlink), runner_uid=os.getuid(), label="fixture"
                )

            binary.chmod(0o720)
            with self.assertRaisesRegex(ValueError, "group/world writable"):
                run_loopback_netns.inspect_runner_artifact(
                    str(binary), runner_uid=os.getuid(), label="fixture"
                )

    def test_artifact_revalidation_rejects_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            binary = self._executable(root, "fixture")
            identity = run_loopback_netns.inspect_runner_artifact(
                str(binary), runner_uid=os.getuid(), label="fixture"
            )
            binary.unlink()
            self._executable(root, "fixture")

            with self.assertRaisesRegex(ValueError, "changed after outer validation"):
                run_loopback_netns.verify_runner_artifact(
                    identity, runner_uid=os.getuid(), label="fixture"
                )

    def test_runner_artifact_rejects_hard_links_without_affecting_support_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            binary = self._executable(root, "fixture")
            os.link(binary, root / "fixture-hardlink")

            with self.assertRaisesRegex(ValueError, "exactly one hard link"):
                run_loopback_netns.inspect_runner_artifact(
                    str(binary), runner_uid=os.getuid(), label="fixture"
                )
            run_loopback_netns._inspect_artifact(
                str(binary),
                allowed_uids={os.getuid()},
                label="support file",
                require_executable=True,
            )

    def test_privileged_bits_require_an_explicit_trusted_tool_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            binary = self._executable(pathlib.Path(temporary), "fixture")
            binary.chmod(0o4700)
            with self.assertRaisesRegex(ValueError, "privileged execution bit"):
                run_loopback_netns._inspect_artifact(
                    str(binary),
                    allowed_uids={os.getuid()},
                    label="fixture",
                    require_executable=True,
                )

            run_loopback_netns._inspect_artifact(
                str(binary),
                allowed_uids={os.getuid()},
                label="fixture",
                require_executable=True,
                allow_privileged_bits=True,
            )

    def test_only_the_fixed_sudo_tool_gets_the_privileged_bit_exception(self) -> None:
        with mock.patch.object(run_loopback_netns, "_inspect_artifact") as inspect:
            run_loopback_netns._inspect_system_tool(
                run_loopback_netns.SUDO, label="sudo"
            )
            run_loopback_netns._inspect_system_tool(
                run_loopback_netns.ENV, label="env"
            )

        self.assertTrue(inspect.call_args_list[0].kwargs["allow_privileged_bits"])
        self.assertFalse(inspect.call_args_list[1].kwargs["allow_privileged_bits"])


class ArgumentAndCommandTests(unittest.TestCase):
    def _identity(self, path: str) -> run_loopback_netns.ArtifactIdentity:
        return run_loopback_netns.ArtifactIdentity(
            path=path,
            device=1,
            inode=2,
            size=3,
            mode=stat.S_IFREG | 0o700,
            uid=1001,
            gid=1002,
            link_count=1,
            mtime_ns=4,
            ctime_ns=5,
        )

    def test_test_name_is_one_exact_rust_test_path(self) -> None:
        name = "providers::codex::supervisor::packaged_smoke::official_tui"
        self.assertEqual(run_loopback_netns.validate_test_name(name), name)
        for invalid in (
            "",
            "official_tui",
            "--ignored",
            "providers::test --ignored",
            "providers::test\nsecond",
            "providers::::test",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    run_loopback_netns.validate_test_name(invalid)

    def test_outer_command_is_fail_closed_sudo_env_and_network_unshare(self) -> None:
        config = run_loopback_netns.LaunchConfig(
            test_binary=self._identity("/runner/target/test"),
            codex_binary=self._identity("/runner/temp/codex"),
            launcher_binary=self._identity("/runner/target/launcher"),
            interpreter=self._identity("/usr/bin/python3.13"),
            script=self._identity("/runner/repo/scripts/run_loopback_netns.py"),
            test_name="providers::codex::official_tui",
            runner_uid=1001,
            runner_gid=1002,
            outer_netns="net:[41]",
        )

        executable, argv, environment = run_loopback_netns.build_outer_exec(config)

        self.assertEqual(executable, run_loopback_netns.SUDO)
        self.assertEqual(
            argv[:4],
            [run_loopback_netns.SUDO, "-n", run_loopback_netns.ENV, "-i"],
        )
        self.assertIn("PATH=" + run_loopback_netns.SAFE_PATH, argv)
        self.assertIn("LC_ALL=C", argv)
        self.assertIn(run_loopback_netns.UNSHARE, argv)
        unshare = argv.index(run_loopback_netns.UNSHARE)
        self.assertEqual(
            argv[unshare + 1 : unshare + 4],
            ["--net", "--fork", "--kill-child=SIGKILL"],
        )
        self.assertIn("--inner-root", argv)
        self.assertEqual(
            environment,
            {"PATH": run_loopback_netns.SAFE_PATH, "LC_ALL": "C"},
        )

    def test_root_command_drops_authority_before_user_verifier(self) -> None:
        config = run_loopback_netns.LaunchConfig(
            test_binary=self._identity("/runner/target/test"),
            codex_binary=self._identity("/runner/temp/codex"),
            launcher_binary=self._identity("/runner/target/launcher"),
            interpreter=self._identity("/usr/bin/python3.13"),
            script=self._identity("/runner/repo/scripts/run_loopback_netns.py"),
            test_name="providers::codex::official_tui",
            runner_uid=1001,
            runner_gid=1002,
            outer_netns="net:[41]",
        )

        executable, argv, environment = run_loopback_netns.build_root_exec(
            config, isolated_netns="net:[42]"
        )

        self.assertEqual(executable, run_loopback_netns.SETPRIV)
        self.assertEqual(
            argv[1:8],
            [
                "--reuid=1001",
                "--regid=1002",
                "--clear-groups",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--no-new-privs",
            ],
        )
        self.assertEqual(argv[8:10], ["--", run_loopback_netns.ENV])
        self.assertEqual(argv[10], "-i")
        self.assertIn("--inner-user", argv)
        self.assertEqual(
            environment,
            {"PATH": run_loopback_netns.SAFE_PATH, "LC_ALL": "C"},
        )


class IsolationVerificationTests(unittest.TestCase):
    def test_proc_status_requires_ids_no_groups_caps_or_new_privileges(self) -> None:
        status = """\
Uid:\t1001\t1001\t1001\t1001
Gid:\t1002\t1002\t1002\t1002
Groups:\t
CapInh:\t0000000000000000
CapPrm:\t0000000000000000
CapEff:\t0000000000000000
CapBnd:\t0000000000000000
CapAmb:\t0000000000000000
NoNewPrivs:\t1
"""
        run_loopback_netns.verify_dropped_process_status(
            status, expected_uid=1001, expected_gid=1002
        )

        mutations = [
            ("Uid:\t1001\t1001\t1001\t1001", "Uid:\t1001\t0\t1001\t1001"),
            ("Gid:\t1002\t1002\t1002\t1002", "Gid:\t1002\t0\t1002\t1002"),
            ("Groups:\t\n", "Groups:\t27\n"),
            ("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
        ]
        mutations.extend(
            (
                f"{capability}:\t0000000000000000",
                f"{capability}:\t0000000000000400",
            )
            for capability in run_loopback_netns.CAPABILITY_FIELDS
        )
        for old, new in mutations:
            with self.subTest(new=new):
                with self.assertRaises(ValueError):
                    run_loopback_netns.verify_dropped_process_status(
                        status.replace(old, new),
                        expected_uid=1001,
                        expected_gid=1002,
                    )

    def test_user_environment_is_an_exact_allowlist(self) -> None:
        expected = run_loopback_netns.expected_user_environment(
            codex_binary="/runner/temp/codex",
            launcher_binary="/runner/target/launcher",
        )
        run_loopback_netns.verify_exact_environment(expected, expected)
        with self.assertRaisesRegex(ValueError, "environment allowlist"):
            run_loopback_netns.verify_exact_environment(
                {**expected, "HTTP_PROXY": "http://proxy.invalid"}, expected
            )

    def test_inherited_fd_scan_rejects_sockets_including_standard_streams(self) -> None:
        run_loopback_netns.verify_no_inherited_socket_fds(
            {0: "/dev/null", 1: "pipe:[1]", 2: "pipe:[2]", 7: "/tmp/log"}
        )
        with self.assertRaisesRegex(ValueError, "socket file descriptor 0"):
            run_loopback_netns.verify_no_inherited_socket_fds(
                {0: "socket:[123]", 1: "pipe:[1]", 2: "pipe:[2]"}
            )

    def test_network_verifier_requires_only_unrouted_up_loopback(self) -> None:
        command_results = {
            (run_loopback_netns.IP, "-4", "route", "show", "table", "main"): (0, ""),
            (run_loopback_netns.IP, "-6", "route", "show", "table", "main"): (0, ""),
            (run_loopback_netns.IP, "-4", "route", "get", "192.0.2.1"): (2, ""),
            (run_loopback_netns.IP, "-4", "route", "get", "198.51.100.1"): (2, ""),
            (run_loopback_netns.IP, "-4", "route", "get", "203.0.113.1"): (2, ""),
            (run_loopback_netns.IP, "-6", "route", "get", "2001:db8::1"): (2, ""),
        }
        valid_flags = run_loopback_netns.IFF_UP | run_loopback_netns.IFF_LOOPBACK

        run_loopback_netns.verify_loopback_only_network(
            interface_names={"lo"},
            loopback_flags=valid_flags,
            command_runner=lambda command: command_results[tuple(command)],
        )

        with self.assertRaisesRegex(ValueError, "unexpected network interfaces"):
            run_loopback_netns.verify_loopback_only_network(
                interface_names={"lo", "eth0"},
                loopback_flags=valid_flags,
                command_runner=lambda command: command_results[tuple(command)],
            )
        for flags in (
            run_loopback_netns.IFF_UP,
            run_loopback_netns.IFF_LOOPBACK,
        ):
            with self.subTest(incomplete_loopback_flags=flags):
                with self.assertRaisesRegex(ValueError, "not an up loopback"):
                    run_loopback_netns.verify_loopback_only_network(
                        interface_names={"lo"},
                        loopback_flags=flags,
                        command_runner=lambda command: command_results[tuple(command)],
                    )
        routed = dict(command_results)
        routed[(run_loopback_netns.IP, "-4", "route", "get", "192.0.2.1")] = (
            0,
            "192.0.2.1 dev eth0",
        )
        with self.assertRaisesRegex(ValueError, "documentation address was routable"):
            run_loopback_netns.verify_loopback_only_network(
                interface_names={"lo"},
                loopback_flags=valid_flags,
                command_runner=lambda command: routed[tuple(command)],
            )

        for family in ("-4", "-6"):
            with self.subTest(nonempty_main_route=family):
                nonempty = dict(command_results)
                route_command = (
                    run_loopback_netns.IP,
                    family,
                    "route",
                    "show",
                    "table",
                    "main",
                )
                nonempty[route_command] = (
                    0,
                    "default dev eth0",
                )
                with self.assertRaisesRegex(ValueError, "route table was not empty"):
                    run_loopback_netns.verify_loopback_only_network(
                        interface_names={"lo"},
                        loopback_flags=valid_flags,
                        command_runner=lambda command: nonempty[tuple(command)],
                    )

        ipv6_routed = dict(command_results)
        ipv6_routed[(run_loopback_netns.IP, "-6", "route", "get", "2001:db8::1")] = (
            0,
            "2001:db8::1 dev eth0",
        )
        with self.assertRaisesRegex(ValueError, "documentation address was routable"):
            run_loopback_netns.verify_loopback_only_network(
                interface_names={"lo"},
                loopback_flags=valid_flags,
                command_runner=lambda command: ipv6_routed[tuple(command)],
            )

        failed_lookup = dict(command_results)
        failed_lookup[(run_loopback_netns.IP, "-4", "route", "get", "192.0.2.1")] = (
            1,
            "",
        )
        with self.assertRaisesRegex(ValueError, "did not report unreachable"):
            run_loopback_netns.verify_loopback_only_network(
                interface_names={"lo"},
                loopback_flags=valid_flags,
                command_runner=lambda command: failed_lookup[tuple(command)],
            )


class UserExecTests(unittest.TestCase):
    def test_user_exec_is_exact_prebuilt_libtest_invocation(self) -> None:
        identity = run_loopback_netns.ArtifactIdentity(
            path="/runner/target/test",
            device=1,
            inode=2,
            size=3,
            mode=stat.S_IFREG | 0o700,
            uid=1001,
            gid=1002,
            link_count=1,
            mtime_ns=4,
            ctime_ns=5,
        )
        environment = run_loopback_netns.expected_user_environment(
            codex_binary="/runner/temp/codex",
            launcher_binary="/runner/target/launcher",
        )

        executable, argv = run_loopback_netns.build_user_test_exec(
            identity,
            test_name="providers::codex::official_tui",
        )

        self.assertEqual(executable, identity.path)
        self.assertEqual(
            argv,
            [
                identity.path,
                "providers::codex::official_tui",
                "--exact",
                "--ignored",
                "--nocapture",
            ],
        )
        self.assertNotIn("cargo", argv)
        self.assertEqual(
            set(environment),
            {
                "PATH",
                "LC_ALL",
                "CALCIFER_CODEX_COMPAT_BINARY",
                "CALCIFER_PACKAGE_TUI_LAUNCHER",
            },
        )


if __name__ == "__main__":
    unittest.main()
