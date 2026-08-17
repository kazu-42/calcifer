"""Verify a signed cargo-binstall of the published Calcifer crate.

This is the public cargo-binstall acceptance helper. It never reads release
signing secrets and never enables compile or QuickInstall fallbacks.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path


DEFAULT_VERSION = "0.1.0-alpha.5"
FORBIDDEN_ENV = ("GH_TOKEN", "GITHUB_TOKEN", "CARGO_REGISTRY_TOKEN")
SIGNED_FLAGS = (
    "--only-signed",
    "--no-discover-github-token",
    "--disable-telemetry",
    "--disable-strategies",
    "quick-install,compile",
    "--no-confirm",
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


Runner = Callable[..., CommandResult]


def binstall_command(
    *,
    binary: Path,
    install_root: Path,
    version: str,
    extra: tuple[str, ...] = (),
    github_token: str | None = None,
) -> list[str]:
    command = [
        str(binary),
        *SIGNED_FLAGS,
        "--root",
        str(install_root),
        *extra,
    ]
    if github_token:
        command.extend(["--github-token", github_token])
    command.append(f"calcifer@={version}")
    return command


def sanitized_environ(environ: Mapping[str, str]) -> dict[str, str]:
    return {key: value for key, value in environ.items() if key not in FORBIDDEN_ENV}


def snapshot_tree(path: Path) -> tuple[tuple[str, int, int], ...]:
    if not path.exists():
        return ()
    entries: list[tuple[str, int, int]] = []
    for child in sorted(path.rglob("*")):
        info = child.lstat()
        entries.append((str(child.relative_to(path)), info.st_mode, info.st_size))
    return tuple(entries)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def installed_binary(install_root: Path) -> Path:
    name = "calcifer.exe" if sys.platform == "win32" else "calcifer"
    return install_root / "bin" / name


def default_runner(
    command: list[str], *, env: dict[str, str], capture_output: bool = False
) -> CommandResult:
    completed = subprocess.run(
        command,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    if not capture_output:
        if completed.stdout:
            sys.stdout.write(completed.stdout)
        if completed.stderr:
            sys.stderr.write(completed.stderr)
    return CommandResult(completed.returncode, completed.stdout, completed.stderr)


def _require_success(result: CommandResult, action: str) -> None:
    if result.returncode != 0:
        raise SystemExit(f"{action} failed with status {result.returncode}")


def _probe_installed(
    binary: Path, env: dict[str, str], version: str, runner: Runner
) -> None:
    version_result = runner([str(binary), "--version"], env=env, capture_output=True)
    _require_success(version_result, "calcifer --version")
    if version not in version_result.stdout:
        raise SystemExit(
            f"calcifer --version did not report {version}: {version_result.stdout!r}"
        )
    help_result = runner([str(binary), "--help"], env=env, capture_output=True)
    _require_success(help_result, "calcifer --help")
    doctor = runner([str(binary), "--json", "doctor"], env=env, capture_output=True)
    _require_success(doctor, "calcifer --json doctor")
    if "doctor" not in doctor.stdout:
        raise SystemExit("calcifer --json doctor did not emit a doctor payload")


def run_verification(
    *,
    cargo_binstall: Path,
    install_root: Path,
    version: str,
    github_token: str | None = None,
    runner: Runner = default_runner,
) -> None:
    if not cargo_binstall.is_file():
        raise SystemExit(f"cargo-binstall is not a file: {cargo_binstall}")
    install_root.mkdir(parents=True, exist_ok=True)
    calcifer_home = Path(tempfile.mkdtemp(prefix="calcifer-binstall-home-"))
    env = sanitized_environ(os.environ)
    env["CALCIFER_HOME"] = str(calcifer_home)
    if github_token:
        # cargo-binstall 1.21 reads GITHUB_TOKEN for some GitHub API calls
        # even when --github-token is also passed. This is an explicit
        # injection, not discovery from git credentials.
        env["GITHUB_TOKEN"] = github_token
    try:
        before = snapshot_tree(calcifer_home)
        installed = installed_binary(install_root)
        _require_success(
            runner(
                binstall_command(
                    binary=cargo_binstall,
                    install_root=install_root,
                    version=version,
                    github_token=github_token,
                ),
                env=env,
            ),
            "signed cargo-binstall",
        )
        if not installed.is_file():
            raise SystemExit(f"signed install did not write {installed}")
        _probe_installed(installed, env, version, runner)
        after_install = snapshot_tree(calcifer_home)
        if after_install != before:
            raise SystemExit("CALCIFER_HOME changed during install or doctor")

        digest = sha256_file(installed)
        _require_success(
            runner(
                binstall_command(
                    binary=cargo_binstall,
                    install_root=install_root,
                    version=version,
                    extra=("--force",),
                    github_token=github_token,
                ),
                env=env,
            ),
            "signed cargo-binstall --force",
        )
        if sha256_file(installed) != digest:
            raise SystemExit("same-version --force replaced the installed digest")

        missing = runner(
            binstall_command(
                binary=cargo_binstall,
                install_root=install_root,
                version="0.1.0-alpha.4",
                extra=("--force",),
                github_token=github_token,
            ),
            env=env,
        )
        if missing.returncode == 0:
            raise SystemExit("missing version unexpectedly installed")
        if sha256_file(installed) != digest:
            raise SystemExit("a failed install replaced the existing binary")

        if os.name == "posix":
            unreadable = Path(tempfile.mkdtemp(prefix="calcifer-binstall-unread-"))
            os.chmod(unreadable, 0)
            try:
                unread_env = dict(env)
                unread_env["CALCIFER_HOME"] = str(unreadable)
                _probe_installed(installed, unread_env, version, runner)
            finally:
                os.chmod(unreadable, stat.S_IRWXU)
                shutil.rmtree(unreadable)
        print(f"signed_binstall_ok version={version} digest={digest}")
    finally:
        shutil.rmtree(calcifer_home, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cargo-binstall",
        type=Path,
        required=True,
        help="Path to a cargo-binstall executable",
    )
    parser.add_argument(
        "--install-root",
        type=Path,
        required=True,
        help="Isolated cargo-binstall --root directory",
    )
    parser.add_argument(
        "--version",
        default=DEFAULT_VERSION,
        help="Exact Calcifer crate version to install",
    )
    parser.add_argument(
        "--github-token",
        default=None,
        help=(
            "Optional explicit GitHub token for public release API rate limits. "
            "This is not credential discovery; GH_TOKEN/GITHUB_TOKEN are still stripped."
        ),
    )
    args = parser.parse_args(argv)
    run_verification(
        cargo_binstall=args.cargo_binstall,
        install_root=args.install_root,
        version=args.version,
        github_token=args.github_token,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
