import tomllib
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PUBLIC_KEY = "RWScrwKKsqmN5v9pAGdgdW0jNSHokfmerI53KJiE2gRNmcaNS36gOtC6"


class BinstallMetadataTests(unittest.TestCase):
    def test_binary_install_metadata_is_exact_and_signed(self) -> None:
        document = tomllib.loads(
            (REPOSITORY_ROOT / "Cargo.toml").read_text(encoding="utf-8")
        )
        package = document["package"]
        self.assertEqual(package["publish"], ["crates-io"])
        self.assertEqual(
            package["include"],
            [
                "/Cargo.lock",
                "/Cargo.toml",
                "/LICENSE",
                "/README.md",
                "/SECURITY.md",
                "/build.rs",
                "/src/**",
            ],
        )

        metadata = package["metadata"]["binstall"]
        self.assertEqual(
            metadata["pkg-url"],
            "{ repo }/releases/download/v{ version }/{ name }-v{ version }-{ target }{ archive-suffix}",
        )
        self.assertEqual(
            metadata["bin-dir"],
            "{ name }-v{ version }-{ target }/{ bin }{ binary-ext}",
        )
        self.assertEqual(metadata["pkg-fmt"], "tgz")
        self.assertEqual(
            metadata["disabled-strategies"], ["quick-install", "compile"]
        )
        self.assertEqual(
            metadata["overrides"]["x86_64-pc-windows-msvc"]["pkg-fmt"],
            "zip",
        )
        self.assertEqual(metadata["signing"]["algorithm"], "minisign")
        self.assertEqual(metadata["signing"]["pubkey"], PUBLIC_KEY)

    def test_internal_runtime_crates_are_publishable_dependencies(self) -> None:
        for crate in ("calcifer-unix-child-fd", "calcifer-macos-acl"):
            document = tomllib.loads(
                (REPOSITORY_ROOT / "crates" / crate / "Cargo.toml").read_text(
                    encoding="utf-8"
                )
            )
            package = document["package"]
            self.assertEqual(package["publish"], ["crates-io"])
            self.assertEqual(
                package["repository"], "https://github.com/kazu-42/calcifer"
            )


if __name__ == "__main__":
    unittest.main()
