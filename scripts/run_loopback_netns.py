#!/usr/bin/env python3
"""Run one prebuilt libtest case in a fail-closed loopback-only Linux netns.

The public (runner-uid) stage validates every executable and the exact test
name before crossing sudo. The root stage creates and proves a fresh network
namespace, enables only loopback, and then irreversibly drops back to the
runner uid with no supplementary groups, capabilities, or new privileges. The
final user stage repeats the proofs before execve'ing the exact libtest binary.

There is deliberately no non-netns fallback. An unavailable isolation tool or
an unverifiable invariant is a test failure, not a reason to run with egress.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence


SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
SAFE_BASE_ENVIRONMENT = {"PATH": SAFE_PATH, "LC_ALL": "C"}

SUDO = "/usr/bin/sudo"
ENV = "/usr/bin/env"
UNSHARE = "/usr/bin/unshare"
SETPRIV = "/usr/bin/setpriv"
IP = "/usr/sbin/ip"

CODEX_BINARY_ENV = "CALCIFER_CODEX_COMPAT_BINARY"
LAUNCHER_BINARY_ENV = "CALCIFER_PACKAGE_TUI_LAUNCHER"

MAX_PATH_BYTES = 4096
MAX_TEST_NAME_BYTES = 1024
NETWORK_COMMAND_TIMEOUT_SECONDS = 10
IFF_UP = 0x1
IFF_LOOPBACK = 0x8
CAPABILITY_FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
DOCUMENTATION_ADDRESSES = (
    ("-4", "192.0.2.1"),
    ("-4", "198.51.100.1"),
    ("-4", "203.0.113.1"),
    ("-6", "2001:db8::1"),
)
TEST_NAME_PATTERN = re.compile(r"[A-Za-z0-9_]+(?:::[A-Za-z0-9_]+)+")
NETNS_PATTERN = re.compile(r"net:\[[0-9]+\]")


@dataclasses.dataclass(frozen=True)
class ArtifactIdentity:
    path: str
    device: int
    inode: int
    size: int
    mode: int
    uid: int
    gid: int
    link_count: int
    mtime_ns: int
    ctime_ns: int

    def encode(self) -> str:
        return json.dumps(
            dataclasses.asdict(self), sort_keys=True, separators=(",", ":")
        )

    @classmethod
    def decode(cls, encoded: str) -> ArtifactIdentity:
        def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
            decoded: dict[str, object] = {}
            for key, value in pairs:
                if key in decoded:
                    raise ValueError("artifact identity contained a duplicate field")
                decoded[key] = value
            return decoded

        try:
            raw = json.loads(encoded, object_pairs_hook=no_duplicate_keys)
        except (json.JSONDecodeError, TypeError) as error:
            raise ValueError("artifact identity was not valid JSON") from error
        expected_fields = {field.name for field in dataclasses.fields(cls)}
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise ValueError("artifact identity fields were not exact")
        path = raw["path"]
        if not isinstance(path, str):
            raise ValueError("artifact identity path was not text")
        numeric: dict[str, int] = {}
        for field in expected_fields - {"path"}:
            value = raw[field]
            if type(value) is not int or value < 0:
                raise ValueError("artifact identity numeric field was invalid")
            numeric[field] = value
        return cls(path=path, **numeric)


@dataclasses.dataclass(frozen=True)
class LaunchConfig:
    test_binary: ArtifactIdentity
    codex_binary: ArtifactIdentity
    launcher_binary: ArtifactIdentity
    interpreter: ArtifactIdentity
    script: ArtifactIdentity
    test_name: str
    runner_uid: int
    runner_gid: int
    outer_netns: str


def _canonical_path(raw_path: str, *, label: str) -> pathlib.Path:
    if not isinstance(raw_path, str) or not raw_path:
        raise ValueError(f"{label} path was empty")
    if len(os.fsencode(raw_path)) > MAX_PATH_BYTES:
        raise ValueError(f"{label} path was oversized")
    path = pathlib.Path(raw_path)
    if not path.is_absolute() or os.path.normpath(raw_path) != raw_path:
        raise ValueError(f"{label} must use an absolute canonical path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{label} could not be resolved") from error
    if str(resolved) != raw_path:
        raise ValueError(f"{label} must use an absolute canonical non-symlink path")
    return path


def _inspect_artifact(
    raw_path: str,
    *,
    allowed_uids: set[int],
    label: str,
    require_executable: bool,
    allow_privileged_bits: bool = False,
    require_single_link: bool = False,
) -> ArtifactIdentity:
    path = _canonical_path(raw_path, label=label)
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ValueError(f"{label} could not be inspected") from error
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"{label} was not a regular file")
    if metadata.st_uid not in allowed_uids:
        raise ValueError(f"{label} was not owned by an allowed uid")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise ValueError(f"{label} was group/world writable")
    if not allow_privileged_bits and metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError(f"{label} had a privileged execution bit")
    if require_executable and not metadata.st_mode & stat.S_IXUSR:
        raise ValueError(f"{label} was not owner-executable")
    if metadata.st_size <= 0:
        raise ValueError(f"{label} was empty")
    if require_single_link and metadata.st_nlink != 1:
        raise ValueError(f"{label} did not have exactly one hard link")
    return ArtifactIdentity(
        path=str(path),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
        link_count=metadata.st_nlink,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


def inspect_runner_artifact(
    raw_path: str, *, runner_uid: int, label: str
) -> ArtifactIdentity:
    return _inspect_artifact(
        raw_path,
        allowed_uids={runner_uid},
        label=label,
        require_executable=True,
        require_single_link=True,
    )


def verify_runner_artifact(
    expected: ArtifactIdentity, *, runner_uid: int, label: str
) -> None:
    observed = inspect_runner_artifact(
        expected.path, runner_uid=runner_uid, label=label
    )
    if observed != expected:
        raise ValueError(f"{label} changed after outer validation")


def _verify_support_artifact(
    expected: ArtifactIdentity,
    *,
    runner_uid: int,
    label: str,
    require_executable: bool,
) -> None:
    observed = _inspect_artifact(
        expected.path,
        allowed_uids={0, runner_uid},
        label=label,
        require_executable=require_executable,
    )
    if observed != expected:
        raise ValueError(f"{label} changed after outer validation")


def validate_test_name(test_name: str) -> str:
    if not isinstance(test_name, str) or not test_name:
        raise ValueError("test name was empty")
    if len(test_name.encode("utf-8")) > MAX_TEST_NAME_BYTES:
        raise ValueError("test name was oversized")
    if TEST_NAME_PATTERN.fullmatch(test_name) is None:
        raise ValueError("test name was not one exact Rust test path")
    return test_name


def _read_netns_identity() -> str:
    try:
        identity = os.readlink("/proc/self/ns/net")
    except OSError as error:
        raise ValueError("network namespace identity was unavailable") from error
    if NETNS_PATTERN.fullmatch(identity) is None:
        raise ValueError("network namespace identity had an unexpected format")
    return identity


def _validate_netns_identity(identity: str, *, label: str) -> str:
    if NETNS_PATTERN.fullmatch(identity) is None:
        raise ValueError(f"{label} network namespace identity was invalid")
    return identity


def _internal_arguments(config: LaunchConfig) -> list[str]:
    return [
        "--test-binary",
        config.test_binary.path,
        "--test-name",
        config.test_name,
        "--codex-binary",
        config.codex_binary.path,
        "--launcher-binary",
        config.launcher_binary.path,
        "--runner-uid",
        str(config.runner_uid),
        "--runner-gid",
        str(config.runner_gid),
        "--outer-netns",
        config.outer_netns,
        "--test-identity",
        config.test_binary.encode(),
        "--codex-identity",
        config.codex_binary.encode(),
        "--launcher-identity",
        config.launcher_binary.encode(),
        "--interpreter-identity",
        config.interpreter.encode(),
        "--script-identity",
        config.script.encode(),
    ]


def build_outer_exec(
    config: LaunchConfig,
) -> tuple[str, list[str], dict[str, str]]:
    argv = [
        SUDO,
        "-n",
        ENV,
        "-i",
        f"PATH={SAFE_PATH}",
        "LC_ALL=C",
        UNSHARE,
        "--net",
        "--fork",
        "--kill-child=SIGKILL",
        "--",
        config.interpreter.path,
        config.script.path,
        "--inner-root",
        *_internal_arguments(config),
    ]
    return SUDO, argv, dict(SAFE_BASE_ENVIRONMENT)


def expected_user_environment(
    *, codex_binary: str, launcher_binary: str
) -> dict[str, str]:
    return {
        **SAFE_BASE_ENVIRONMENT,
        CODEX_BINARY_ENV: codex_binary,
        LAUNCHER_BINARY_ENV: launcher_binary,
    }


def build_root_exec(
    config: LaunchConfig, *, isolated_netns: str
) -> tuple[str, list[str], dict[str, str]]:
    user_environment = expected_user_environment(
        codex_binary=config.codex_binary.path,
        launcher_binary=config.launcher_binary.path,
    )
    environment_arguments = [
        f"{key}={value}" for key, value in user_environment.items()
    ]
    argv = [
        SETPRIV,
        f"--reuid={config.runner_uid}",
        f"--regid={config.runner_gid}",
        "--clear-groups",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        "--",
        ENV,
        "-i",
        *environment_arguments,
        config.interpreter.path,
        config.script.path,
        "--inner-user",
        "--isolated-netns",
        isolated_netns,
        *_internal_arguments(config),
    ]
    return SETPRIV, argv, dict(SAFE_BASE_ENVIRONMENT)


def build_user_test_exec(
    test_binary: ArtifactIdentity, *, test_name: str
) -> tuple[str, list[str]]:
    return (
        test_binary.path,
        [
            test_binary.path,
            validate_test_name(test_name),
            "--exact",
            "--ignored",
            "--nocapture",
        ],
    )


def _run_ip(command: Sequence[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(
            list(command),
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=NETWORK_COMMAND_TIMEOUT_SECONDS,
            env=SAFE_BASE_ENVIRONMENT,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("network isolation command could not complete") from error
    return result.returncode, result.stdout


def verify_loopback_only_network(
    *,
    interface_names: set[str],
    loopback_flags: int,
    command_runner: Callable[[Sequence[str]], tuple[int, str]] = _run_ip,
) -> None:
    if interface_names != {"lo"}:
        raise ValueError("network namespace had unexpected network interfaces")
    if loopback_flags & (IFF_UP | IFF_LOOPBACK) != IFF_UP | IFF_LOOPBACK:
        raise ValueError("loopback interface was not an up loopback device")
    for family in ("-4", "-6"):
        status, output = command_runner([IP, family, "route", "show", "table", "main"])
        if status != 0:
            raise ValueError("main route table could not be inspected")
        if output.strip():
            raise ValueError("main route table was not empty")
    for family, address in DOCUMENTATION_ADDRESSES:
        status, _output = command_runner([IP, family, "route", "get", address])
        if status == 0:
            raise ValueError(f"documentation address was routable: {address}")
        if status != 2:
            raise ValueError(
                f"documentation address lookup did not report unreachable: {address}"
            )


def _observe_loopback_network() -> tuple[set[str], int]:
    try:
        names = set(os.listdir("/sys/class/net"))
        flags_text = pathlib.Path("/sys/class/net/lo/flags").read_text(
            encoding="ascii"
        )
        flags = int(flags_text.strip(), 16)
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError("loopback network state could not be inspected") from error
    return names, flags


def _enable_and_verify_loopback_network() -> None:
    status, _output = _run_ip([IP, "link", "set", "dev", "lo", "up"])
    if status != 0:
        raise ValueError("loopback interface could not be enabled")
    names, flags = _observe_loopback_network()
    verify_loopback_only_network(interface_names=names, loopback_flags=flags)


def _verify_current_loopback_network() -> None:
    names, flags = _observe_loopback_network()
    verify_loopback_only_network(interface_names=names, loopback_flags=flags)


def verify_dropped_process_status(
    status_text: str, *, expected_uid: int, expected_gid: int
) -> None:
    fields: dict[str, str] = {}
    for line in status_text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if key in fields:
            raise ValueError("process status contained a duplicate field")
        fields[key] = value.strip()

    expected_uids = [str(expected_uid)] * 4
    expected_gids = [str(expected_gid)] * 4
    if fields.get("Uid", "").split() != expected_uids:
        raise ValueError("real/effective/saved/filesystem uids were not exact")
    if fields.get("Gid", "").split() != expected_gids:
        raise ValueError("real/effective/saved/filesystem gids were not exact")
    if fields.get("Groups") != "":
        raise ValueError("supplementary groups were not empty")
    for capability in CAPABILITY_FIELDS:
        value = fields.get(capability)
        try:
            parsed = int(value, 16) if value is not None else -1
        except ValueError as error:
            raise ValueError(f"{capability} was malformed") from error
        if parsed != 0:
            raise ValueError(f"{capability} was not zero")
    if fields.get("NoNewPrivs") != "1":
        raise ValueError("NoNewPrivs was not one")


def verify_exact_environment(
    observed: Mapping[str, str], expected: Mapping[str, str]
) -> None:
    if dict(observed) != dict(expected):
        raise ValueError("user-stage environment allowlist was not exact")


def _read_open_fd_links() -> dict[int, str]:
    links: dict[int, str] = {}
    try:
        names = os.listdir("/proc/self/fd")
    except OSError as error:
        raise ValueError("open file descriptors could not be enumerated") from error
    for name in names:
        if not name.isdecimal():
            raise ValueError("open file descriptor entry was not numeric")
        descriptor = int(name)
        try:
            links[descriptor] = os.readlink(f"/proc/self/fd/{name}")
        except FileNotFoundError:
            # The directory descriptor used by listdir may have closed before
            # readlink. Every persistent inherited descriptor remains visible.
            continue
        except OSError as error:
            raise ValueError("open file descriptor could not be inspected") from error
    return links


def verify_no_inherited_socket_fds(fd_links: Mapping[int, str]) -> None:
    for descriptor, target in fd_links.items():
        if target.startswith("socket:["):
            raise ValueError(f"inherited socket file descriptor {descriptor} remained")


def _verify_artifacts(config: LaunchConfig) -> None:
    verify_runner_artifact(
        config.test_binary, runner_uid=config.runner_uid, label="test binary"
    )
    verify_runner_artifact(
        config.codex_binary, runner_uid=config.runner_uid, label="Codex binary"
    )
    verify_runner_artifact(
        config.launcher_binary,
        runner_uid=config.runner_uid,
        label="launcher binary",
    )
    _verify_support_artifact(
        config.interpreter,
        runner_uid=config.runner_uid,
        label="Python interpreter",
        require_executable=True,
    )
    _verify_support_artifact(
        config.script,
        runner_uid=config.runner_uid,
        label="netns helper script",
        require_executable=False,
    )


def _inspect_system_tool(path: str, *, label: str) -> None:
    _inspect_artifact(
        path,
        allowed_uids={0},
        label=label,
        require_executable=True,
        # sudo is intentionally setuid-root on the GitHub runner. This narrow
        # exception is safe only because system tools must be canonical,
        # root-owned, non-writable regular files at fixed absolute paths.
        allow_privileged_bits=path == SUDO,
    )


def _assert_linux() -> None:
    if not sys.platform.startswith("linux"):
        raise ValueError("loopback-only network namespaces require Linux")


def _validate_runner_ids(uid: int, gid: int) -> None:
    if type(uid) is not int or uid <= 0:
        raise ValueError("runner uid must be a non-root positive integer")
    if type(gid) is not int or gid <= 0:
        raise ValueError("runner gid must be a non-root positive integer")


def _public_config(arguments: argparse.Namespace) -> LaunchConfig:
    _assert_linux()
    uid = os.getuid()
    gid = os.getgid()
    _validate_runner_ids(uid, gid)
    if os.geteuid() != uid or os.getegid() != gid:
        raise ValueError("outer stage refused a set-id process")
    test_name = validate_test_name(arguments.test_name)
    interpreter_path = str(pathlib.Path(sys.executable).resolve(strict=True))
    script_path = str(pathlib.Path(__file__).resolve(strict=True))
    config = LaunchConfig(
        test_binary=inspect_runner_artifact(
            arguments.test_binary, runner_uid=uid, label="test binary"
        ),
        codex_binary=inspect_runner_artifact(
            arguments.codex_binary, runner_uid=uid, label="Codex binary"
        ),
        launcher_binary=inspect_runner_artifact(
            arguments.launcher_binary, runner_uid=uid, label="launcher binary"
        ),
        interpreter=_inspect_artifact(
            interpreter_path,
            allowed_uids={0, uid},
            label="Python interpreter",
            require_executable=True,
        ),
        script=_inspect_artifact(
            script_path,
            allowed_uids={0, uid},
            label="netns helper script",
            require_executable=False,
        ),
        test_name=test_name,
        runner_uid=uid,
        runner_gid=gid,
        outer_netns=_read_netns_identity(),
    )
    for tool, label in (
        (SUDO, "sudo"),
        (ENV, "env"),
        (UNSHARE, "unshare"),
        (SETPRIV, "setpriv"),
        (IP, "ip"),
    ):
        _inspect_system_tool(tool, label=label)
    return config


def _internal_config(arguments: argparse.Namespace) -> LaunchConfig:
    uid = arguments.runner_uid
    gid = arguments.runner_gid
    _validate_runner_ids(uid, gid)
    config = LaunchConfig(
        test_binary=ArtifactIdentity.decode(arguments.test_identity),
        codex_binary=ArtifactIdentity.decode(arguments.codex_identity),
        launcher_binary=ArtifactIdentity.decode(arguments.launcher_identity),
        interpreter=ArtifactIdentity.decode(arguments.interpreter_identity),
        script=ArtifactIdentity.decode(arguments.script_identity),
        test_name=validate_test_name(arguments.test_name),
        runner_uid=uid,
        runner_gid=gid,
        outer_netns=_validate_netns_identity(arguments.outer_netns, label="outer"),
    )
    public_paths = (
        (arguments.test_binary, config.test_binary.path, "test binary"),
        (arguments.codex_binary, config.codex_binary.path, "Codex binary"),
        (arguments.launcher_binary, config.launcher_binary.path, "launcher binary"),
    )
    for public_path, identity_path, label in public_paths:
        if public_path != identity_path:
            raise ValueError(f"{label} path did not match its outer identity")
    return config


def _run_outer(arguments: argparse.Namespace) -> None:
    config = _public_config(arguments)
    executable, argv, environment = build_outer_exec(config)
    os.execve(executable, argv, environment)


def _run_inner_root(arguments: argparse.Namespace) -> None:
    _assert_linux()
    if os.geteuid() != 0 or os.getuid() != 0:
        raise ValueError("inner root stage did not have exact root identity")
    config = _internal_config(arguments)
    _verify_artifacts(config)
    isolated_netns = _read_netns_identity()
    if isolated_netns == config.outer_netns:
        raise ValueError("unshare did not create a distinct network namespace")
    _enable_and_verify_loopback_network()
    executable, argv, environment = build_root_exec(
        config, isolated_netns=isolated_netns
    )
    os.execve(executable, argv, environment)


def _read_process_status() -> str:
    try:
        return pathlib.Path("/proc/self/status").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ValueError("process status could not be inspected") from error


def _run_inner_user(arguments: argparse.Namespace) -> None:
    _assert_linux()
    config = _internal_config(arguments)
    isolated_netns = _validate_netns_identity(
        arguments.isolated_netns, label="isolated"
    )
    if _read_netns_identity() != isolated_netns or isolated_netns == config.outer_netns:
        raise ValueError("user stage did not remain in the distinct network namespace")
    if (
        os.getuid() != config.runner_uid
        or os.geteuid() != config.runner_uid
        or os.getgid() != config.runner_gid
        or os.getegid() != config.runner_gid
        or os.getgroups() != []
    ):
        raise ValueError("user stage process identity was not exact")
    verify_dropped_process_status(
        _read_process_status(),
        expected_uid=config.runner_uid,
        expected_gid=config.runner_gid,
    )
    expected_environment = expected_user_environment(
        codex_binary=config.codex_binary.path,
        launcher_binary=config.launcher_binary.path,
    )
    verify_exact_environment(os.environ, expected_environment)
    verify_no_inherited_socket_fds(_read_open_fd_links())
    _verify_artifacts(config)
    _verify_current_loopback_network()
    executable, argv = build_user_test_exec(
        config.test_binary, test_name=config.test_name
    )
    os.execve(executable, argv, expected_environment)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run one exact prebuilt libtest case in a loopback-only Linux netns"
    )
    parser.add_argument("--test-binary", required=True)
    parser.add_argument("--test-name", required=True)
    parser.add_argument("--codex-binary", required=True)
    parser.add_argument("--launcher-binary", required=True)
    stage = parser.add_mutually_exclusive_group()
    stage.add_argument("--inner-root", action="store_true", help=argparse.SUPPRESS)
    stage.add_argument("--inner-user", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--runner-uid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--runner-gid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--outer-netns", help=argparse.SUPPRESS)
    parser.add_argument("--isolated-netns", help=argparse.SUPPRESS)
    parser.add_argument("--test-identity", help=argparse.SUPPRESS)
    parser.add_argument("--codex-identity", help=argparse.SUPPRESS)
    parser.add_argument("--launcher-identity", help=argparse.SUPPRESS)
    parser.add_argument("--interpreter-identity", help=argparse.SUPPRESS)
    parser.add_argument("--script-identity", help=argparse.SUPPRESS)
    return parser


def _require_internal_arguments(arguments: argparse.Namespace) -> None:
    required = (
        "runner_uid",
        "runner_gid",
        "outer_netns",
        "test_identity",
        "codex_identity",
        "launcher_identity",
        "interpreter_identity",
        "script_identity",
    )
    missing = [name for name in required if getattr(arguments, name) is None]
    if arguments.inner_user and arguments.isolated_netns is None:
        missing.append("isolated_netns")
    if missing:
        raise ValueError("inner stage omitted required sealed arguments")


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.inner_root or arguments.inner_user:
            _require_internal_arguments(arguments)
        else:
            internal_values = (
                arguments.runner_uid,
                arguments.runner_gid,
                arguments.outer_netns,
                arguments.isolated_netns,
                arguments.test_identity,
                arguments.codex_identity,
                arguments.launcher_identity,
                arguments.interpreter_identity,
                arguments.script_identity,
            )
            if any(value is not None for value in internal_values):
                raise ValueError("public stage refused internal-only arguments")

        if arguments.inner_root:
            _run_inner_root(arguments)
        elif arguments.inner_user:
            _run_inner_user(arguments)
        else:
            _run_outer(arguments)
    except (OSError, ValueError) as error:
        print(f"loopback netns gate failed: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
