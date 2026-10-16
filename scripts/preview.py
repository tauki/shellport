"""Disposable local browser preview. This password is synthetic, never production."""
import os
import pathlib
import subprocess

project = pathlib.Path(__file__).resolve().parents[1]
data = project / ".work" / "preview"
data.mkdir(parents=True, exist_ok=True, mode=0o700)
password = data / "synthetic-password.txt"
password.write_text("synthetic-preview-password\n")
password.chmod(0o600)
binary = project / "bin" / "shellport"
if not (data / "config.json").exists():
    subprocess.run([str(binary), "init", "--data-dir", str(data), "--password-file", str(password), "--origin", "http://127.0.0.1:8088", "--local-shell", "--tmux-mode", "managed", "--yes"], check=True)
    subprocess.run([str(binary), "add-host", "--data-dir", str(data), "--name", "Preview server", "--address", "127.0.0.1", "--user", "demo", "--auth", "local"], check=True)
os.execv(str(binary), [str(binary), "serve", "--data-dir", str(data), "--listen", "127.0.0.1:8088"])
