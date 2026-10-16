"""Verify published archive metadata cannot identify the build machine's owner."""
import io
import tarfile
import re
from pathlib import Path
import unittest

from release import portable_member, add_documentation, release_notes, ROOT, DOCUMENTS
import tempfile


class ArchivePrivacyTest(unittest.TestCase):
    def test_downloads_include_project_license_and_public_verification_key(self):
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            add_documentation(tar, "download")
        archive.seek(0)
        with tarfile.open(fileobj=archive) as tar:
            for name in ("LICENSE", "shellport-release-key.pem"):
                self.assertEqual(tar.extractfile("download/" + name).read(), (ROOT / name).read_bytes())

    def test_documentation_images_resolve_in_downloaded_archive(self):
        archive=io.BytesIO()
        with tarfile.open(fileobj=archive,mode="w:gz") as tar:
            add_documentation(tar,"download")
        archive.seek(0)
        with tarfile.open(fileobj=archive) as tar:
            for document in DOCUMENTS:
                if not document.endswith(".md"): continue
                source=(ROOT/document).read_text()
                images=re.findall(r'<img[^>]+src="([^"]+)"',source)+re.findall(r'!\[[^\]]*\]\(([^)]+)\)',source)
                for image in images:
                    if "://" in image: continue
                    member=tar.getmember("download/"+str(Path(document).parent/image))
                    self.assertTrue(member.isfile())
                    self.assertEqual((member.uid,member.gid,member.uname,member.gname,member.pax_headers),(0,0,"","",{}))
                    self.assertEqual(tar.extractfile(member).read(),(ROOT/Path(document).parent/image).read_bytes())

    def test_owner_and_extended_metadata_are_removed_without_changing_files(self):
        payload = b"release file contents"
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            for name, mode in (("shellport", 0o755), ("README.md", 0o644)):
                member = tarfile.TarInfo("shellport-v1.2.3-linux-amd64/" + name)
                member.size = len(payload)
                member.mode = mode
                member.uid, member.gid = 501, 20
                member.uname, member.gname = "private-builder", "private-group"
                member.mtime = 1720000000
                member.pax_headers = {"uname": "private-builder", "gid": "20", "mtime": "1720000000.123"}
                tar.addfile(portable_member(member), io.BytesIO(payload))
        archive.seek(0)
        with tarfile.open(fileobj=archive) as tar:
            for member, expected_mode in zip(tar.getmembers(), (0o755, 0o644)):
                self.assertEqual((member.uid, member.gid, member.uname, member.gname, member.mtime), (0, 0, "", "", 0))
                self.assertEqual(member.pax_headers, {})
                self.assertEqual(member.mode, expected_mode)
                self.assertEqual(tar.extractfile(member).read(), payload)


class ReleaseNotesTest(unittest.TestCase):
    def test_matching_version_does_not_publish_unreleased_or_older_notes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"CHANGELOG.md").write_text("# Changelog\n\n## [Unreleased]\nFuture work\n\n## [0.1.0] - 2026-10-14\nFirst release\n\n## [0.0.1]\nOld work\n")
            notes = release_notes("v0.1.0",root)
            self.assertIn("Shellport v0.1.0",notes)
            self.assertIn("First release",notes)
            self.assertNotIn("Future work",notes)
            self.assertNotIn("Old work",notes)
            self.assertIn("Future work",release_notes("v0.2.0-rc.1",root))

    def test_missing_or_empty_notes_refuse_packaging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in ("# Changelog\n", "## [Unreleased]\n\n"):
                (root/"CHANGELOG.md").write_text(source)
                with self.assertRaises(ValueError): release_notes("v0.1.0",root)


if __name__ == "__main__":
    unittest.main()
