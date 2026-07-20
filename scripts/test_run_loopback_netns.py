import dataclasses
import os
import pathlib
import stat
import struct
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

    def test_ip_alias_is_resolved_before_the_canonical_target_is_inspected(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary).resolve(strict=True)
            target = self._executable(root, "ip-target")
            alias = root / "ip-alias"
            alias.symlink_to(target)
            expected = run_loopback_netns.ArtifactIdentity(
                path=str(target),
                device=1,
                inode=2,
                size=3,
                mode=stat.S_IFREG | 0o755,
                uid=0,
                gid=0,
                link_count=1,
                mtime_ns=4,
                ctime_ns=5,
            )

            with mock.patch.object(
                run_loopback_netns, "_inspect_artifact", return_value=expected
            ) as inspect:
                observed = run_loopback_netns._resolve_system_tool_alias(
                    str(alias), label="ip"
                )

        self.assertEqual(observed, expected)
        inspect.assert_called_once_with(
            str(target),
            allowed_uids={0},
            label="ip",
            require_executable=True,
            allow_privileged_bits=False,
        )

    def test_system_tool_identity_revalidation_rejects_replacement(self) -> None:
        expected = run_loopback_netns.ArtifactIdentity(
            path="/usr/libexec/iproute2/ip",
            device=1,
            inode=2,
            size=3,
            mode=stat.S_IFREG | 0o755,
            uid=0,
            gid=0,
            link_count=1,
            mtime_ns=4,
            ctime_ns=5,
        )
        replacement = dataclasses.replace(expected, inode=3)

        with mock.patch.object(
            run_loopback_netns, "_inspect_artifact", return_value=replacement
        ):
            with self.assertRaisesRegex(
                ValueError, "ip changed after outer validation"
            ):
                run_loopback_netns._verify_system_tool(expected, label="ip")


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
            ip_tool=self._identity("/usr/libexec/iproute2/ip"),
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
        self.assertIn("--ip-path", argv)
        self.assertEqual(argv[argv.index("--ip-path") + 1], config.ip_tool.path)
        self.assertIn("--ip-identity", argv)
        self.assertEqual(
            argv[argv.index("--ip-identity") + 1], config.ip_tool.encode()
        )
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
            ip_tool=self._identity("/usr/libexec/iproute2/ip"),
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

    def test_internal_ip_path_must_match_its_sealed_outer_identity(self) -> None:
        config = run_loopback_netns.LaunchConfig(
            test_binary=self._identity("/runner/target/test"),
            codex_binary=self._identity("/runner/temp/codex"),
            launcher_binary=self._identity("/runner/target/launcher"),
            interpreter=self._identity("/usr/bin/python3.13"),
            script=self._identity("/runner/repo/scripts/run_loopback_netns.py"),
            ip_tool=self._identity("/usr/libexec/iproute2/ip"),
            test_name="providers::codex::official_tui",
            runner_uid=1001,
            runner_gid=1002,
            outer_netns="net:[41]",
        )
        arguments = run_loopback_netns._parser().parse_args(
            ["--inner-root", *run_loopback_netns._internal_arguments(config)]
        )

        self.assertEqual(run_loopback_netns._internal_config(arguments), config)
        arguments.ip_path = "/usr/sbin/ip"
        with self.assertRaisesRegex(
            ValueError, "ip path did not match its outer identity"
        ):
            run_loopback_netns._internal_config(arguments)

    def test_stage_artifact_revalidation_includes_the_sealed_ip_identity(
        self,
    ) -> None:
        config = run_loopback_netns.LaunchConfig(
            test_binary=self._identity("/runner/target/test"),
            codex_binary=self._identity("/runner/temp/codex"),
            launcher_binary=self._identity("/runner/target/launcher"),
            interpreter=self._identity("/usr/bin/python3.13"),
            script=self._identity("/runner/repo/scripts/run_loopback_netns.py"),
            ip_tool=self._identity("/usr/libexec/iproute2/ip"),
            test_name="providers::codex::official_tui",
            runner_uid=1001,
            runner_gid=1002,
            outer_netns="net:[41]",
        )

        with mock.patch.object(
            run_loopback_netns, "verify_runner_artifact"
        ), mock.patch.object(run_loopback_netns, "_verify_support_artifact"):
            with mock.patch.object(
                run_loopback_netns, "_verify_system_tool"
            ) as verify_ip:
                run_loopback_netns._verify_artifacts(config)

        verify_ip.assert_called_once_with(config.ip_tool, label="ip")


class IsolationVerificationTests(unittest.TestCase):
    def test_fallback_allowlist_matches_kernel_created_tunnel_devices(self) -> None:
        self.assertEqual(
            run_loopback_netns.KERNEL_FALLBACK_TUNNEL_INTERFACES,
            frozenset(
                {
                    "tunl0",
                    "gre0",
                    "gretap0",
                    "erspan0",
                    "sit0",
                    "ip6tnl0",
                    "ip6gre0",
                    "ip_vti0",
                    "ip6_vti0",
                }
            ),
        )

    def test_network_observer_uses_current_netns_not_inherited_sysfs(self) -> None:
        flag_reads: list[str] = []

        def read_flags(interface_name: str) -> int:
            flag_reads.append(interface_name)
            return run_loopback_netns.IFF_LOOPBACK

        with mock.patch.object(
            os,
            "listdir",
            side_effect=AssertionError("inherited sysfs must not be observed"),
        ):
            observed = run_loopback_netns._observe_loopback_network(
                interface_enumerator=lambda: [(1, "lo")],
                flag_reader=read_flags,
            )

        self.assertEqual(observed, {"lo": run_loopback_netns.IFF_LOOPBACK})
        self.assertEqual(flag_reads, ["lo"])

    def test_network_observer_defaults_to_current_netns_kernel_apis(self) -> None:
        with (
            mock.patch.object(
                os,
                "listdir",
                side_effect=AssertionError("inherited sysfs must not be observed"),
            ),
            mock.patch.object(
                run_loopback_netns.socket,
                "if_nameindex",
                return_value=[(7, "lo")],
            ) as interface_enumerator,
            mock.patch.object(
                run_loopback_netns,
                "_read_interface_flags",
                return_value=run_loopback_netns.IFF_LOOPBACK,
            ) as flag_reader,
        ):
            observed = run_loopback_netns._observe_loopback_network()

        self.assertEqual(observed, {"lo": run_loopback_netns.IFF_LOOPBACK})
        interface_enumerator.assert_called_once_with()
        flag_reader.assert_called_once_with("lo")

    def test_network_observer_rejects_ambiguous_interface_entries(self) -> None:
        invalid_entries = (
            [(1, "lo"), (1, "sit0")],
            [(1, "lo"), (2, "lo")],
            [(0, "lo")],
            [(1, "")],
            [(1, "x" * 16)],
            [(1, "lo\x00escape")],
        )

        for entries in invalid_entries:
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(
                    ValueError, "network state could not be inspected"
                ):
                    run_loopback_netns._observe_loopback_network(
                        interface_enumerator=lambda entries=entries: entries,
                        flag_reader=lambda _interface_name: 0,
                    )

    def test_network_observer_rejects_malformed_or_unbounded_kernel_results(
        self,
    ) -> None:
        invalid_entries = (
            ["not-a-tuple"],
            [(1, "lo", "extra")],
            [("1", "lo")],
            [(1, 42)],
            [
                (index + 1, f"n{index}")
                for index in range(
                    run_loopback_netns.MAX_NETWORK_INTERFACES + 1
                )
            ],
        )
        for entries in invalid_entries:
            with self.subTest(entries=entries):
                with self.assertRaisesRegex(
                    ValueError, "network state could not be inspected"
                ):
                    run_loopback_netns._observe_loopback_network(
                        interface_enumerator=lambda entries=entries: entries,
                        flag_reader=lambda _interface_name: 0,
                    )

        for flags in (None, True, -1, 0x10000):
            with self.subTest(flags=flags):
                with self.assertRaisesRegex(
                    ValueError, "network state could not be inspected"
                ):
                    run_loopback_netns._observe_loopback_network(
                        interface_enumerator=lambda: [(1, "lo")],
                        flag_reader=lambda _interface_name, flags=flags: flags,
                    )

    def test_interface_flag_reader_uses_linux_ioctl_and_closes_socket(self) -> None:
        expected_flags = run_loopback_netns.IFF_UP | run_loopback_netns.IFF_LOOPBACK
        response = bytearray(256)
        struct.pack_into("=H", response, 16, expected_flags)
        socket_factory = mock.MagicMock()
        control_socket = socket_factory.return_value.__enter__.return_value
        control_socket.fileno.return_value = 41

        with (
            mock.patch.object(
                run_loopback_netns.socket, "socket", socket_factory
            ),
            mock.patch.object(
                run_loopback_netns.fcntl,
                "ioctl",
                return_value=bytes(response),
            ) as ioctl,
        ):
            flags = run_loopback_netns._read_interface_flags("lo")

        self.assertEqual(flags, expected_flags)
        socket_factory.assert_called_once_with(
            run_loopback_netns.socket.AF_INET,
            run_loopback_netns.socket.SOCK_DGRAM,
        )
        control_socket.fileno.assert_called_once_with()
        ioctl.assert_called_once()
        descriptor, request_code, request = ioctl.call_args.args
        self.assertEqual(descriptor, 41)
        self.assertEqual(request_code, run_loopback_netns.SIOCGIFFLAGS)
        self.assertEqual(len(request), 256)
        self.assertEqual(request[:16], b"lo" + (b"\x00" * 14))
        socket_factory.return_value.__exit__.assert_called_once()

    def test_interface_flag_reader_rejects_invalid_or_failed_ioctl_results(
        self,
    ) -> None:
        invalid_results = (bytearray(256), b"\x00" * 17)
        for result in invalid_results:
            with self.subTest(result_type=type(result).__name__, size=len(result)):
                socket_factory = mock.MagicMock()
                control_socket = socket_factory.return_value.__enter__.return_value
                control_socket.fileno.return_value = 41
                with (
                    mock.patch.object(
                        run_loopback_netns.socket, "socket", socket_factory
                    ),
                    mock.patch.object(
                        run_loopback_netns.fcntl, "ioctl", return_value=result
                    ),
                    self.assertRaisesRegex(
                        ValueError, "flags response was invalid"
                    ),
                ):
                    run_loopback_netns._read_interface_flags("lo")
                socket_factory.return_value.__exit__.assert_called_once()

        socket_factory = mock.MagicMock()
        with (
            mock.patch.object(
                run_loopback_netns.socket, "socket", socket_factory
            ),
            mock.patch.object(
                run_loopback_netns.fcntl,
                "ioctl",
                side_effect=OSError("injected"),
            ),
            self.assertRaisesRegex(ValueError, "flags could not be inspected"),
        ):
            run_loopback_netns._read_interface_flags("lo")
        socket_factory.return_value.__exit__.assert_called_once()

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
        ip_path = "/usr/libexec/iproute2/ip"
        command_results = {
            (ip_path, "-4", "route", "show", "table", "main"): (0, ""),
            (ip_path, "-6", "route", "show", "table", "main"): (0, ""),
            (ip_path, "-4", "route", "get", "192.0.2.1"): (2, ""),
            (ip_path, "-4", "route", "get", "198.51.100.1"): (2, ""),
            (ip_path, "-4", "route", "get", "203.0.113.1"): (2, ""),
            (ip_path, "-6", "route", "get", "2001:db8::1"): (2, ""),
        }
        valid_flags = run_loopback_netns.IFF_UP | run_loopback_netns.IFF_LOOPBACK

        run_loopback_netns.verify_loopback_only_network(
            interface_flags={"lo": valid_flags},
            ip_path=ip_path,
            command_runner=lambda command: command_results[tuple(command)],
        )

        with self.assertRaisesRegex(ValueError, "non-loopback interface was up"):
            run_loopback_netns.verify_loopback_only_network(
                interface_flags={
                    "lo": valid_flags,
                    "eth0": run_loopback_netns.IFF_UP,
                },
                ip_path=ip_path,
                command_runner=lambda command: command_results[tuple(command)],
            )
        for flags in (
            run_loopback_netns.IFF_UP,
            run_loopback_netns.IFF_LOOPBACK,
        ):
            with self.subTest(incomplete_loopback_flags=flags):
                with self.assertRaisesRegex(ValueError, "not an up loopback"):
                    run_loopback_netns.verify_loopback_only_network(
                        interface_flags={"lo": flags},
                        ip_path=ip_path,
                        command_runner=lambda command: command_results[tuple(command)],
                    )
        routed = dict(command_results)
        routed[(ip_path, "-4", "route", "get", "192.0.2.1")] = (
            0,
            "192.0.2.1 dev eth0",
        )
        with self.assertRaisesRegex(ValueError, "documentation address was routable"):
            run_loopback_netns.verify_loopback_only_network(
                interface_flags={"lo": valid_flags},
                ip_path=ip_path,
                command_runner=lambda command: routed[tuple(command)],
            )

        for family in ("-4", "-6"):
            with self.subTest(nonempty_main_route=family):
                nonempty = dict(command_results)
                route_command = (
                    ip_path,
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
                        interface_flags={"lo": valid_flags},
                        ip_path=ip_path,
                        command_runner=lambda command: nonempty[tuple(command)],
                    )

        ipv6_routed = dict(command_results)
        ipv6_routed[(ip_path, "-6", "route", "get", "2001:db8::1")] = (
            0,
            "2001:db8::1 dev eth0",
        )
        with self.assertRaisesRegex(ValueError, "documentation address was routable"):
            run_loopback_netns.verify_loopback_only_network(
                interface_flags={"lo": valid_flags},
                ip_path=ip_path,
                command_runner=lambda command: ipv6_routed[tuple(command)],
            )

        failed_lookup = dict(command_results)
        failed_lookup[(ip_path, "-4", "route", "get", "192.0.2.1")] = (
            1,
            "",
        )
        with self.assertRaisesRegex(ValueError, "did not report unreachable"):
            run_loopback_netns.verify_loopback_only_network(
                interface_flags={"lo": valid_flags},
                ip_path=ip_path,
                command_runner=lambda command: failed_lookup[tuple(command)],
            )

    def test_network_verifier_accepts_only_down_non_loopback_fallback_devices(
        self,
    ) -> None:
        ip_path = "/usr/libexec/iproute2/ip"
        command_results = {
            (ip_path, "-4", "route", "show", "table", "main"): (0, ""),
            (ip_path, "-6", "route", "show", "table", "main"): (0, ""),
            (ip_path, "-4", "route", "get", "192.0.2.1"): (2, ""),
            (ip_path, "-4", "route", "get", "198.51.100.1"): (2, ""),
            (ip_path, "-4", "route", "get", "203.0.113.1"): (2, ""),
            (ip_path, "-6", "route", "get", "2001:db8::1"): (2, ""),
        }
        fallback_interfaces = ("sit0", "ip6tnl0", "ip_vti0", "ip6_vti0")
        for interface in fallback_interfaces:
            for family in ("-4", "-6"):
                command_results[
                    (ip_path, family, "-o", "address", "show", "dev", interface)
                ] = (0, "")
                command_results[
                    (
                        ip_path,
                        family,
                        "route",
                        "show",
                        "table",
                        "all",
                        "dev",
                        interface,
                    )
                ] = (0, "")
        valid_loopback = run_loopback_netns.IFF_UP | run_loopback_netns.IFF_LOOPBACK

        run_loopback_netns.verify_loopback_only_network(
            interface_flags={
                "lo": valid_loopback,
                **{interface: 0 for interface in fallback_interfaces},
            },
            ip_path=ip_path,
            command_runner=lambda command: command_results[tuple(command)],
        )

        with self.assertRaisesRegex(ValueError, "non-loopback interface was up"):
            run_loopback_netns.verify_loopback_only_network(
                interface_flags={
                    "lo": valid_loopback,
                    "sit0": run_loopback_netns.IFF_UP,
                },
                ip_path=ip_path,
                command_runner=lambda command: command_results[tuple(command)],
            )

        with self.assertRaisesRegex(ValueError, "unexpected non-loopback"):
            run_loopback_netns.verify_loopback_only_network(
                interface_flags={"lo": valid_loopback, "eth0": 0},
                ip_path=ip_path,
                command_runner=lambda command: command_results[tuple(command)],
            )

        addressed = dict(command_results)
        addressed[(ip_path, "-4", "-o", "address", "show", "dev", "sit0")] = (
            0,
            "2: sit0 inet 192.0.2.2/32 scope global sit0",
        )
        with self.assertRaisesRegex(ValueError, "assigned address"):
            run_loopback_netns.verify_loopback_only_network(
                interface_flags={"lo": valid_loopback, "sit0": 0},
                ip_path=ip_path,
                command_runner=lambda command: addressed[tuple(command)],
            )

        routed = dict(command_results)
        routed[
            (ip_path, "-6", "route", "show", "table", "all", "dev", "ip6tnl0")
        ] = (0, "2001:db8::/32 dev ip6tnl0")
        with self.assertRaisesRegex(ValueError, "had a route"):
            run_loopback_netns.verify_loopback_only_network(
                interface_flags={"lo": valid_loopback, "ip6tnl0": 0},
                ip_path=ip_path,
                command_runner=lambda command: routed[tuple(command)],
            )

    def test_root_network_setup_forces_only_allowlisted_fallback_devices_down(
        self,
    ) -> None:
        ip_path = "/usr/libexec/iproute2/ip"
        valid_loopback = run_loopback_netns.IFF_UP | run_loopback_netns.IFF_LOOPBACK
        observations = (
            {
                "lo": run_loopback_netns.IFF_LOOPBACK,
                "sit0": run_loopback_netns.IFF_UP,
                "ip6tnl0": run_loopback_netns.IFF_UP,
                "ip_vti0": run_loopback_netns.IFF_UP,
                "ip6_vti0": run_loopback_netns.IFF_UP,
            },
            {
                "lo": valid_loopback,
                "sit0": 0,
                "ip6tnl0": 0,
                "ip_vti0": 0,
                "ip6_vti0": 0,
            },
        )
        observer_calls = 0
        commands: list[tuple[str, ...]] = []

        def command_runner(command: list[str]) -> tuple[int, str]:
            commands.append(tuple(command))
            if "get" in command:
                return 2, ""
            return 0, ""

        def network_observer() -> dict[str, int]:
            nonlocal observer_calls
            observation = observations[observer_calls]
            observer_calls += 1
            return observation

        run_loopback_netns._enable_and_verify_loopback_network(
            ip_path=ip_path,
            command_runner=command_runner,
            network_observer=network_observer,
        )

        self.assertEqual(observer_calls, 2)
        self.assertEqual(
            commands[:5],
            [
                (ip_path, "link", "set", "dev", "ip6_vti0", "down"),
                (ip_path, "link", "set", "dev", "ip6tnl0", "down"),
                (ip_path, "link", "set", "dev", "ip_vti0", "down"),
                (ip_path, "link", "set", "dev", "sit0", "down"),
                (ip_path, "link", "set", "dev", "lo", "up"),
            ],
        )
        for interface in ("ip6_vti0", "ip6tnl0", "ip_vti0", "sit0"):
            for family in ("-4", "-6"):
                self.assertIn(
                    (ip_path, family, "-o", "address", "show", "dev", interface),
                    commands,
                )
                self.assertIn(
                    (
                        ip_path,
                        family,
                        "route",
                        "show",
                        "table",
                        "all",
                        "dev",
                        interface,
                    ),
                    commands,
                )
        for family in ("-4", "-6"):
            self.assertIn(
                (ip_path, family, "route", "show", "table", "main"),
                commands,
            )
        for family, address in run_loopback_netns.DOCUMENTATION_ADDRESSES:
            self.assertIn(
                (ip_path, family, "route", "get", address),
                commands,
            )

        unknown_commands: list[tuple[str, ...]] = []

        def unknown_runner(command: list[str]) -> tuple[int, str]:
            unknown_commands.append(tuple(command))
            return 0, ""

        with self.assertRaisesRegex(ValueError, "unexpected non-loopback"):
            run_loopback_netns._enable_and_verify_loopback_network(
                ip_path=ip_path,
                command_runner=unknown_runner,
                network_observer=lambda: {
                    "lo": valid_loopback,
                    "eth0": run_loopback_netns.IFF_UP,
                },
            )
        self.assertEqual(
            unknown_commands,
            [],
        )

        with self.assertRaisesRegex(ValueError, "could not be disabled"):
            run_loopback_netns._enable_and_verify_loopback_network(
                ip_path=ip_path,
                command_runner=lambda command: (
                    (1, "")
                    if command[-2:] == ["sit0", "down"]
                    else (0, "")
                ),
                network_observer=lambda: {
                    "lo": valid_loopback,
                    "sit0": run_loopback_netns.IFF_UP,
                },
            )

    def test_root_network_setup_rejects_a_post_observation_unknown_interface(
        self,
    ) -> None:
        ip_path = "/usr/libexec/iproute2/ip"
        valid_loopback = run_loopback_netns.IFF_UP | run_loopback_netns.IFF_LOOPBACK
        observations = iter(
            (
                {
                    "lo": run_loopback_netns.IFF_LOOPBACK,
                    "sit0": run_loopback_netns.IFF_UP,
                },
                {
                    "lo": valid_loopback,
                    "sit0": 0,
                    "eth0": 0,
                },
            )
        )
        commands: list[tuple[str, ...]] = []

        def command_runner(command: list[str]) -> tuple[int, str]:
            commands.append(tuple(command))
            return 0, ""

        with self.assertRaisesRegex(ValueError, "unexpected non-loopback"):
            run_loopback_netns._enable_and_verify_loopback_network(
                ip_path=ip_path,
                command_runner=command_runner,
                network_observer=lambda: next(observations),
            )

        self.assertEqual(
            commands,
            [
                (ip_path, "link", "set", "dev", "sit0", "down"),
                (ip_path, "link", "set", "dev", "lo", "up"),
            ],
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
