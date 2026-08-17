from pathlib import Path
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPOSITORY_ROOT / ".github" / "workflows" / "signed-binstall.yml"


class SignedBinstallWorkflowContractTests(unittest.TestCase):
    def test_workflow_is_path_and_dispatch_only_with_read_permissions(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("  workflow_dispatch:\n", workflow)
        self.assertIn("  pull_request:\n", workflow)
        self.assertIn("      - .github/workflows/signed-binstall.yml\n", workflow)
        self.assertIn("      - scripts/verify_signed_binstall.py\n", workflow)
        self.assertIn("      - scripts/test_verify_signed_binstall.py\n", workflow)
        self.assertIn("      - scripts/test_binstall_verification_workflow.py\n", workflow)
        self.assertIn("  contents: read\n", workflow)
        self.assertNotIn("id-token:", workflow)
        self.assertNotIn("packages:", workflow)

    def test_workflow_never_touches_release_signing_secrets(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertNotIn("release-signing", workflow)
        self.assertNotIn("MINISIGN_PRIVATE_KEY", workflow)
        self.assertNotIn("secrets.", workflow)

    def test_matrix_covers_the_remaining_native_targets(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("ubuntu-22.04\n", workflow)
        self.assertIn("ubuntu-22.04-arm\n", workflow)
        self.assertIn("windows-latest\n", workflow)
        self.assertIn("x86_64-unknown-linux-gnu\n", workflow)
        self.assertIn("aarch64-unknown-linux-gnu\n", workflow)
        self.assertIn("x86_64-pc-windows-msvc\n", workflow)
        self.assertNotIn("macos-", workflow)

    def test_installs_pinned_cargo_binstall_and_runs_the_verifier(self) -> None:
        workflow = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("CARGO_BINSTALL_VERSION: 1.21.1\n", workflow)
        self.assertIn(
            "d8ff7fd6567cf80d438c6c143484a81e84bd237e2507aa0f85b5707beced0bbc",
            workflow,
        )
        self.assertIn(
            "1ff106d1e20182f7da77265f60e24e419f81b85fe6264cf4df9bdcdf5bb021bd",
            workflow,
        )
        self.assertIn(
            "27aee4e73cd8b1d479730cb9cdbd89b1114453a135689d4ee1a7e7f913f0ffe1",
            workflow,
        )
        self.assertIn("python3 scripts/verify_signed_binstall.py", workflow)
        self.assertIn('--github-token "${github_token}"', workflow)
        self.assertIn("GH_API_TOKEN: ${{ github.token }}", workflow)
        self.assertIn('github_token="${GH_API_TOKEN:?}"', workflow)
        self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", workflow)
        exe_check = workflow.index("cargo-binstall.exe")
        unix_check = workflow.index(
            'calcifer-cargo-binstall/cargo-binstall" ]]; then\n'
        )
        self.assertLess(exe_check, unix_check)
        script = (
            REPOSITORY_ROOT / "scripts" / "verify_signed_binstall.py"
        ).read_text(encoding="utf-8")
        self.assertIn("--only-signed", script)
        self.assertIn("quick-install,compile", script)
        self.assertIn("--no-discover-github-token", script)


if __name__ == "__main__":
    unittest.main()
