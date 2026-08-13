import json
import tempfile
import unittest
from pathlib import Path

from scripts import generate_homebrew_formula, release_manifest


class GenerateHomebrewFormulaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.root = Path(self.temporary_directory.name)
        self.manifest = self.root / release_manifest.MANIFEST_NAME
        self.output = self.root / "calcifer-preview.rb"
        self.document = {
            "attestations": {
                "artifact": {
                    "job": "publish",
                    "kind": "github_artifact_attestation",
                    "subjects": "release_assets",
                    "workflow": release_manifest.RELEASE_WORKFLOW,
                },
                "immutable_release": {
                    "kind": "github_release_attestation",
                    "required": True,
                },
                "signer_workflow": {
                    "repository": release_manifest.REPOSITORY,
                    "workflow": release_manifest.RELEASE_WORKFLOW,
                },
            },
            "product": "calcifer",
            "release_channel": "preview",
            "repository": release_manifest.REPOSITORY,
            "schema": release_manifest.MANIFEST_SCHEMA,
            "source_commit": "0123456789abcdef0123456789abcdef01234567",
            "tag": "v0.1.0-alpha.4",
            "tag_ref_digest": "89abcdef0123456789abcdef0123456789abcdef",
            "targets": [self._target(target) for target in release_manifest.SUPPORTED_TARGETS],
            "version": "0.1.0-alpha.4",
        }
        self._write_manifest()

    def _target(self, target: str) -> dict[str, object]:
        metadata = release_manifest.TARGET_METADATA[target]
        archive_name = release_manifest.archive_name("0.1.0-alpha.4", target)
        prefix = f"calcifer-v0.1.0-alpha.4-{target}"
        return {
            "archive": {
                "format": metadata["format"],
                "name": archive_name,
                "sha256": (target.encode().hex() + ("0" * 64))[:64],
                "size": 1024,
            },
            "architecture": metadata["architecture"],
            "binary": {
                "path": f'{prefix}/{metadata["binary"]}',
                "sha256": (target[::-1].encode().hex() + ("1" * 64))[:64],
            },
            "libc": metadata["libc"],
            "os": metadata["os"],
            "runtime_requirements": metadata["runtime_requirements"],
            "target": target,
        }

    def _write_manifest(self) -> None:
        self.manifest.write_bytes(
            json.dumps(
                self.document,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            + b"\n"
        )

    def test_generates_exact_four_target_preview_formula(self) -> None:
        document = generate_homebrew_formula.load_manifest(self.manifest)
        rendered = generate_homebrew_formula.render_formula(document)

        self.assertIn("class CalciferPreview < Formula", rendered)
        self.assertIn("v0.1.0-alpha.4", rendered)
        self.assertNotIn('  version "', rendered)
        self.assertEqual(rendered.count("  on_macos do"), 1)
        self.assertEqual(rendered.count("  on_linux do"), 1)
        self.assertEqual(rendered.count("      url "), 4)
        self.assertNotIn("x86_64-pc-windows-msvc", rendered)
        self.assertIn('    bin.install "calcifer"', rendered)
        self.assertNotIn("post_install", rendered)

    def test_rejects_noncanonical_or_tampered_manifest(self) -> None:
        self.manifest.write_text(json.dumps(self.document, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "canonical"):
            generate_homebrew_formula.load_manifest(self.manifest)

        self._write_manifest()
        document = json.loads(self.manifest.read_bytes())
        document["targets"][0]["archive"]["sha256"] = "0" * 63
        self.manifest.write_bytes(
            json.dumps(document, separators=(",", ":"), sort_keys=True).encode() + b"\n"
        )
        with self.assertRaisesRegex(ValueError, "archive digest"):
            generate_homebrew_formula.load_manifest(self.manifest)

    def test_rejects_stable_release_for_preview_formula(self) -> None:
        self.document["version"] = "0.1.0"
        self.document["tag"] = "v0.1.0"
        self.document["release_channel"] = "stable"
        self._write_manifest()
        with self.assertRaisesRegex(ValueError, "preview release"):
            generate_homebrew_formula.load_manifest(self.manifest)

    def test_atomic_write_refuses_symbolic_link_output(self) -> None:
        sentinel = self.root / "sentinel"
        sentinel.write_text("unchanged", encoding="utf-8")
        self.output.symlink_to(sentinel)
        with self.assertRaisesRegex(ValueError, "symbolic link"):
            generate_homebrew_formula.write_formula(
                output=self.output,
                rendered="formula\n",
            )
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")


if __name__ == "__main__":
    unittest.main()
