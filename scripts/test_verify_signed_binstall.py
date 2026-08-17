import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_signed_binstall


class VerifySignedBinstallTests(unittest.TestCase):
    def test_binstall_command_is_signed_only_and_disables_fallbacks(self) -> None:
        command = verify_signed_binstall.binstall_command(
            binary=Path("/opt/cargo-binstall"),
            install_root=Path("/tmp/root"),
            version="0.1.0-alpha.5",
            extra=("--force",),
        )

        self.assertEqual(
            command[:8],
            [
                "/opt/cargo-binstall",
                "--only-signed",
                "--no-discover-github-token",
                "--disable-telemetry",
                "--disable-strategies",
                "quick-install,compile",
                "--no-confirm",
                "--root",
            ],
        )
        self.assertEqual(command[8], "/tmp/root")
        self.assertIn("--force", command)
        self.assertEqual(command[-1], "calcifer@=0.1.0-alpha.5")
        self.assertNotIn("compile", command[-1])
        joined = " ".join(command)
        self.assertNotIn("--skip-signatures", joined)
        self.assertNotIn("quick-install,compile,compile", joined)
        self.assertNotIn("--github-token", joined)

    def test_explicit_github_token_is_a_flag_not_an_env_var(self) -> None:
        command = verify_signed_binstall.binstall_command(
            binary=Path("cargo-binstall"),
            install_root=Path("/tmp/root"),
            version="0.1.0-alpha.5",
            github_token="ghs_test",
        )
        self.assertIn("--no-discover-github-token", command)
        token_at = command.index("--github-token")
        self.assertEqual(command[token_at + 1], "ghs_test")

    def test_sanitized_environ_drops_github_and_registry_tokens(self) -> None:
        cleaned = verify_signed_binstall.sanitized_environ(
            {
                "PATH": "/usr/bin",
                "GH_TOKEN": "secret",
                "GITHUB_TOKEN": "secret",
                "CARGO_REGISTRY_TOKEN": "secret",
                "CALCIFER_HOME": "/tmp/empty",
            }
        )

        self.assertEqual(cleaned["PATH"], "/usr/bin")
        self.assertEqual(cleaned["CALCIFER_HOME"], "/tmp/empty")
        self.assertNotIn("GH_TOKEN", cleaned)
        self.assertNotIn("GITHUB_TOKEN", cleaned)
        self.assertNotIn("CARGO_REGISTRY_TOKEN", cleaned)

    def test_directory_snapshot_is_stable_and_detects_new_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            empty = verify_signed_binstall.snapshot_tree(root)
            self.assertEqual(empty, ())
            (root / "profiles.json").write_text("{}\n", encoding="utf-8")
            changed = verify_signed_binstall.snapshot_tree(root)
            self.assertNotEqual(changed, empty)
            self.assertEqual(changed[0][0], "profiles.json")

    def test_digest_file_is_sha256_hex(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "calcifer"
            path.write_bytes(b"calcifer")
            digest = verify_signed_binstall.sha256_file(path)
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertEqual(digest, digest.lower())

    def test_default_version_matches_the_published_alpha(self) -> None:
        self.assertEqual(verify_signed_binstall.DEFAULT_VERSION, "0.1.0-alpha.5")


class VerifySignedBinstallRunnerTests(unittest.TestCase):
    def test_child_environment_never_receives_tokens(self) -> None:
        recorded: dict[str, str] = {}

        def fake_run(
            command: list[str], *, env: dict[str, str], capture_output: bool = False
        ) -> verify_signed_binstall.CommandResult:
            del capture_output
            recorded.update(env)
            joined = " ".join(command)
            if "0.1.0-alpha.4" in joined:
                return verify_signed_binstall.CommandResult(76, "", "no version")
            if "--json" in command:
                return verify_signed_binstall.CommandResult(
                    0, '{"schema_version":1,"command":"doctor"}\n', ""
                )
            return verify_signed_binstall.CommandResult(0, "calcifer 0.1.0-alpha.5\n", "")

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            binary = root / "cargo-binstall"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            os.chmod(binary, 0o755)
            installed = root / "install" / "bin" / "calcifer"
            installed.parent.mkdir(parents=True)
            installed.write_bytes(b"ok")
            os.chmod(installed, 0o755)
            with patch.dict(
                os.environ,
                {
                    "GH_TOKEN": "secret",
                    "GITHUB_TOKEN": "secret",
                    "CARGO_REGISTRY_TOKEN": "secret",
                },
                clear=False,
            ):
                verify_signed_binstall.run_verification(
                    cargo_binstall=binary,
                    install_root=root / "install",
                    version="0.1.0-alpha.5",
                    runner=fake_run,
                )
        self.assertNotIn("GH_TOKEN", recorded)
        self.assertNotIn("GITHUB_TOKEN", recorded)
        self.assertNotIn("CARGO_REGISTRY_TOKEN", recorded)


if __name__ == "__main__":
    unittest.main()
