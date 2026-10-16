"""Keep release signing credentials out of packaging and toolchain processes."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import release


KEY = "test-signing-key-sentinel"


class PackagingSecretTest(unittest.TestCase):
    def run_packaging(self, version, sign=False, fail_compile=False):
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "internal/web/dist").mkdir(parents=True)
            (root / "internal/web/dist/index.html").write_text("test")
            (root / "web/public").mkdir(parents=True)
            (root / "web/public/third-party-notices.txt").write_text("notices")
            (root / "CHANGELOG.md").write_text("## [Unreleased]\nRelease test\n")

            def child(command, **kwargs):
                env = kwargs.get("env", os.environ)
                calls.append((command, dict(env)))
                if command[0] == "git":
                    return "a" * 40
                if command[:2] == ["go", "build"]:
                    if fail_compile and command[-1] == "./scripts/release-signing":
                        raise subprocess.CalledProcessError(1, command)
                    Path(command[command.index("-o") + 1]).write_bytes(b"test binary")
                return subprocess.CompletedProcess(command, 0)

            with patch.object(release, "ROOT", root), patch.object(release, "release_notes", return_value="notes"), patch.object(release, "add_documentation"), patch.object(release.subprocess, "run", side_effect=child), patch.object(release.subprocess, "check_output", side_effect=child), patch.dict(os.environ, {"SHELLPORT_RELEASE_SIGNING_KEY": KEY}), patch.object(sys, "argv", ["release.py", version] + (["--sign"] if sign else [])):
                if fail_compile:
                    with self.assertRaises(subprocess.CalledProcessError):
                        release.main()
                    self.assertFalse((root / "bundle/releases" / version).exists())
                else:
                    release.main()
                    output = root / "bundle/releases" / version
                    self.assertEqual(len(list(output.glob("*.tar.gz"))), 5)
                    self.assertEqual(len((output / "SHA256SUMS").read_text().splitlines()), 5)
                    self.assertEqual((output / "RELEASE_NOTES.md").read_text(), "notes")
        return calls

    def test_unsigned_stable_and_prerelease_never_forward_inherited_key(self):
        for version in ("v1.2.3", "v1.2.3-beta.1", "v1.2.3-rc.1"):
            with self.subTest(version=version):
                calls = self.run_packaging(version)
                self.assertEqual(len(calls), 6)  # Git plus all five cross-builds.
                for command, env in calls:
                    self.assertTrue("SHELLPORT_RELEASE_SIGNING_KEY" not in env, command)

    def test_local_signed_packages_give_key_only_to_compiled_signer(self):
        for version in ("v1.2.3", "v1.2.3-beta.1", "v1.2.3-rc.1"):
            with self.subTest(version=version):
                calls = self.run_packaging(version, sign=True)
                tool_calls, signer = calls[:-1], calls[-1]
                self.assertEqual(len(tool_calls), 7)
                for command, env in tool_calls:
                    self.assertTrue("SHELLPORT_RELEASE_SIGNING_KEY" not in env, command)
                self.assertNotEqual(signer[0][0], "go")
                self.assertEqual(signer[1]["SHELLPORT_RELEASE_SIGNING_KEY"], KEY)
                self.assertIn("--checksums", signer[0])

    def test_signer_compilation_failure_leaves_no_release(self):
        calls = self.run_packaging("v1.2.3", sign=True, fail_compile=True)
        self.assertEqual(len(calls), 7)
        for command, env in calls:
            self.assertTrue("SHELLPORT_RELEASE_SIGNING_KEY" not in env, command)


class WorkflowSecretTest(unittest.TestCase):
    def test_only_isolated_signer_step_receives_key_for_every_release(self):
        workflow = (release.ROOT / ".github/workflows/release.yml").read_text()
        jobs = dict(re.findall(r"^  ([a-z]+):\n(.*?)(?=^  [a-z]+:|\Z)", workflow, re.M | re.S))
        self.assertNotIn("SHELLPORT_RELEASE_SIGNING_KEY", jobs["build"])
        self.assertNotIn("--sign", jobs["build"])
        self.assertEqual(workflow.count("${{ secrets.SHELLPORT_RELEASE_SIGNING_KEY }}"), 1)
        signer = jobs["sign"]
        self.assertNotRegex(signer, r"(?m)^\s+if:")
        self.assertIn("environment: release-signing", signer)
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", signer)
        self.assertIn('git merge-base --is-ancestor "$RELEASE_COMMIT" HEAD', signer)
        self.assertIn("cache: false", signer)
        self.assertLess(signer.index("go build"), signer.index("secrets.SHELLPORT_RELEASE_SIGNING_KEY"))
        self.assertIn('"$RUNNER_TEMP/release-signer" --checksums unsigned/SHA256SUMS --output signatures', signer)
        self.assertIn("needs: [build, sign]", jobs["publish"])
        self.assertIn("if: ${{ !cancelled() && needs.build.result == 'success' && needs.sign.result == 'success' }}", jobs["publish"])
        self.assertNotIn("always()", jobs["publish"])
        self.assertNotIn("skipped", jobs["publish"])
        self.assertNotRegex(jobs["publish"], r"(?m)^        if:")
        self.assertIn("name: release-signatures", jobs["publish"])
        self.assertIn("openssl pkeyutl -verify", jobs["publish"])
        self.assertLess(jobs["publish"].index("openssl pkeyutl -verify"), jobs["publish"].index("gh release create"))
        self.assertIn('if [[ "$RELEASE_TAG" == *-* ]]; then\n            options+=(--prerelease)', jobs["publish"])


if __name__ == "__main__":
    unittest.main()
