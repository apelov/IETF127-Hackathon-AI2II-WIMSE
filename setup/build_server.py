"""Copy the installed Maurice executable into the experiment for hashing by AI2II."""
import pathlib
import shutil
import stat

root = pathlib.Path(__file__).resolve().parent.parent
source = shutil.which("maurice")
if not source:
    raise SystemExit("maurice executable not found on PATH")
target = root / "bin/maurice"
target.parent.mkdir(exist_ok=True)
shutil.copyfile(source, target)
target.chmod(target.stat().st_mode | stat.S_IXUSR)
print(f"copied Maurice executable: {target}")
