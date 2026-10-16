"""Package server binaries after make build; never publish or change Git state."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    ("linux-amd64", "linux", "amd64", None),
    ("linux-arm64", "linux", "arm64", None),
    ("linux-armv7", "linux", "arm", "7"),
    ("darwin-arm64", "darwin", "arm64", None),
    ("darwin-amd64", "darwin", "amd64", None),
)

DOCUMENTS=("LICENSE","shellport-release-key.pem","README.md","INSTALL.md","llms.txt","HOWIUSEIT.md","SCREENSHOTS.md","CHANGELOG.md","BACKUP.md","web/public/icon.svg")
SCREENSHOTS=(
    "desktop-terminal.jpg", "desktop-sessions.jpg", "phone-login.jpg",
    "phone-terminal.jpg", "phone-sessions.jpg", "phone-settings.jpg",
    "phone-lifetime.jpg", "phone-direct-shell.jpg", "phone-security.jpg",
)


def add_documentation(tar,prefix,root=ROOT):
    for relative in (*DOCUMENTS,*(f"assets/screenshots/{name}" for name in SCREENSHOTS)):
        tar.add(root / relative,arcname=f"{prefix}/{relative}",filter=portable_member)


def portable_member(member):
    """Keep release files independent of the publisher's account and timestamps."""
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    member.mtime = 0
    member.pax_headers = {}
    return member


def packaging_environment():
    """No packaging, source inspection or compiler subprocess may receive the key."""
    env = dict(os.environ)
    env.pop("SHELLPORT_RELEASE_SIGNING_KEY", None)
    return env


def sign_checksums(checksums, output, key):
    # Compile before giving credentials to the signer; go run would expose them
    # to the Go toolchain as well as the final program.
    env = packaging_environment()
    with tempfile.TemporaryDirectory(prefix="shellport-signer-") as temporary:
        signer = Path(temporary) / "release-signer"
        subprocess.run(
            ["go", "build", "-trimpath", "-o", str(signer), "./scripts/release-signing"],
            cwd=ROOT, env=env, check=True,
        )
        subprocess.run(
            [str(signer), "--checksums", str(checksums), "--output", str(output)],
            cwd=ROOT, env=dict(env, SHELLPORT_RELEASE_SIGNING_KEY=key), check=True,
        )


def source_revision():
    try:
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, env=packaging_environment(), text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return revision if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) else "unknown"


def release_notes(version, root=ROOT):
    sections = {}
    heading = None
    for line in (root / "CHANGELOG.md").read_text().splitlines():
        match = re.match(r"^## \[([^]]+)\]", line)
        if match:
            heading = match.group(1)
            sections[heading] = []
        elif heading is not None:
            sections[heading].append(line)
    selected = sections.get(version.removeprefix("v"), sections.get("Unreleased", []))
    body = "\n".join(selected).strip()
    if not body:
        raise ValueError("CHANGELOG.md needs notes for this version or an Unreleased section")
    return f"# Shellport {version}\n\n{body}\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="release tag, such as v0.1.0 or v0.1.0-rc.1")
    parser.add_argument("--sign", action="store_true", help="sign SHA256SUMS for every platform download")
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?", args.version):
        parser.error("version must be vMAJOR.MINOR.PATCH, optionally with a prerelease suffix")
    if args.sign and not os.environ.get("SHELLPORT_RELEASE_SIGNING_KEY"):
        parser.error("signing requires SHELLPORT_RELEASE_SIGNING_KEY")

    notices = ROOT / "web/public/third-party-notices.txt"
    if not (ROOT / "internal/web/dist/index.html").is_file() or not notices.is_file():
        parser.error("run npm ci and make build before packaging a release")

    notes = release_notes(args.version)
    revision = source_revision()
    output = ROOT / "bundle/releases" / args.version
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        parser.error(f"release output already exists: {output}")

    # Stage the complete set so a failed cross-build never looks like a release.
    with tempfile.TemporaryDirectory(prefix=".release-", dir=output.parent) as temporary:
        stage = Path(temporary)
        checksums = []
        for target, goos, goarch, goarm in TARGETS:
            name = f"shellport-{args.version}-{target}"
            package = stage / name
            package.mkdir()
            env = dict(packaging_environment(), CGO_ENABLED="0", GOOS=goos, GOARCH=goarch)
            if goarm:
                env["GOARM"] = goarm
            print(f"Building {target}", flush=True)
            subprocess.run(
                ["go", "build", "-trimpath", "-ldflags", f"-X main.version={args.version} -X main.commit={revision}", "-o", str(package / "shellport"), "./cmd/shellport"],
                cwd=ROOT, env=env, check=True,
            )
            archive = stage / f"{name}.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                tar.add(package / "shellport", arcname=f"{name}/shellport", filter=portable_member)
                add_documentation(tar,name)
                tar.add(notices, arcname=f"{name}/third-party-notices.txt", filter=portable_member)
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            checksums.append(f"{digest}  {archive.name}\n")
            (package / "shellport").unlink()
            package.rmdir()
        (stage / "SHA256SUMS").write_text("".join(checksums))
        (stage / "RELEASE_NOTES.md").write_text(notes)
        if args.sign:
            sign_checksums(stage / "SHA256SUMS", stage, os.environ["SHELLPORT_RELEASE_SIGNING_KEY"])
        stage.rename(output)
    print(f"Release packages ready in {output}")


if __name__ == "__main__":
    main()
