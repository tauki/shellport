"""Bundle license notices for dependencies embedded in the executable."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
dependencies = [
    ("xterm.js", root / "node_modules/@xterm/xterm/LICENSE"),
    ("xterm.js Fit addon", root / "node_modules/@xterm/addon-fit/LICENSE"),
    ("Manrope font", root / "node_modules/@fontsource-variable/manrope/LICENSE"),
]
# Go runtime dependencies are pinned in go.mod/go.sum; read their actual module licenses.
import json
import subprocess
modules = subprocess.check_output(["go", "list", "-deps", "-f", "{{if .Module}}{{.Module.Path}}{{end}}", "./cmd/shellport"], cwd=root, text=True)
for module in sorted(set(modules.split()) - {"shellport"}):
    info = json.loads(subprocess.check_output(["go", "list", "-m", "-json", module], cwd=root))
    folder = Path(info["Dir"])
    license_file = next((folder / name for name in ["LICENSE", "LICENSE.txt", "LICENSE.md"] if (folder / name).exists()), None)
    if license_file is None:
        raise RuntimeError(f"No license file found for {module}")
    dependencies.append((module, license_file))
text = "Shellport third-party notices\n\n" + "\n\n".join(name + "\n" + "=" * len(name) + "\n" + path.read_text() for name, path in dependencies)
(root / "web/public/third-party-notices.txt").write_text(text)
