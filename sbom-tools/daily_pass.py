# sbom-tools/daily_pass.py
#
# One daily pass without the web app, for Windows Task Scheduler: the same
# monitor job the app runs (ui_app.auto_monitor_versions: empty the version
# caches, stop if PyPI / npm are unreachable, refresh every row, then write
# today's snapshot).
#
#   already done   today's snapshot exists: exit 0 at once (cheap, so the task
#                  can be triggered several times a day)
#   lock           %TEMP%\sbom_daily_pass.lock stops a second pass while one
#                  runs (exit 0); a lock older than 20 h is left over from a
#                  crash or power cut and is removed
#   exit code      0 = today's snapshot exists, 1 = it doesn't (offline,
#                  database down, failed snapshot or an error)
#
# Everything printed goes to the screen and to logs/daily_pass_YYYY-MM-DD.log.
#     python sbom-tools/daily_pass.py

import argparse
import contextlib
import os
import sys
import tempfile
import time
import traceback
from datetime import date, datetime
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = TOOLS_DIR.parent
for path in (str(TOOLS_DIR), str(PROJECT_ROOT)):
    if path not in sys.path:
        sys.path.insert(0, path)

DEFAULT_LOG_DIR = PROJECT_ROOT / "logs"
DEFAULT_LOCK = Path(tempfile.gettempdir()) / "sbom_daily_pass.lock"
STALE_LOCK_HOURS = 20


class Tee:
    """Writes to several streams; a stream that fails (no console) is skipped."""

    def __init__(self, *streams):
        self.streams = [s for s in streams if s is not None]

    def write(self, text):
        for stream in self.streams:
            try:
                stream.write(text)
            except UnicodeEncodeError:
                encoding = getattr(stream, "encoding", None) or "ascii"
                stream.write(text.encode(encoding, "replace").decode(encoding))
            except (OSError, ValueError):
                pass
        return len(text)

    def flush(self):
        for stream in self.streams:
            try:
                stream.flush()
            except (OSError, ValueError):
                pass


def take_lock(path, clock=time.time):
    """(taken, message). A lock older than STALE_LOCK_HOURS is replaced."""
    path = Path(path)
    for attempt in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            try:
                age_hours = (clock() - path.stat().st_mtime) / 3600
            except FileNotFoundError:
                continue                                  # released meanwhile: try again
            if age_hours < STALE_LOCK_HOURS or attempt:
                return False, (f"Another pass is running (lock {path}, {age_hours:.1f} h old); "
                               "nothing to do.")
            path.unlink(missing_ok=True)
            print(f"Removed a stale lock ({age_hours:.1f} h old, left by a crash or power cut).")
            continue
        with os.fdopen(fd, "w") as f:
            f.write(f"pid {os.getpid()} started {datetime.now():%Y-%m-%d %H:%M:%S}\n")
        return True, f"Lock taken: {path}"
    return False, f"Could not take the lock {path}."


def run_pass(today, lock_path, clock):
    import db_storage
    db = db_storage.get_db_storage()

    try:
        done = db.snapshot_done(today)
    except Exception as e:
        print(f"Database not reachable ({type(e).__name__}: {e}). Is XAMPP MySQL running?")
        return 1
    if done:
        print(f"Today's snapshot already exists (run {done}); nothing to do.")
        return 0

    taken, message = take_lock(lock_path, clock)
    print(message)
    if not taken:
        return 0

    try:
        import ui_app
        ui_app.auto_monitor_versions()
        done = db.snapshot_done(today)
        if done:
            print(f"Pass complete: snapshot run {done}.")
            return 0
        print("Pass finished without a snapshot for today (offline, no scans or a failed "
              "snapshot; see above). The next trigger will try again.")
        return 1
    except Exception:
        traceback.print_exc()
        return 1
    finally:
        Path(lock_path).unlink(missing_ok=True)


def main(argv=None, today=None, lock_path=None, log_dir=None, clock=time.time):
    argparse.ArgumentParser(
        description="One daily pass: refresh every row, then today's snapshot."
    ).parse_args(argv)

    today = today or date.today()
    log_dir = Path(log_dir or DEFAULT_LOG_DIR)
    log_dir.mkdir(parents=True, exist_ok=True)

    with open(log_dir / f"daily_pass_{today.isoformat()}.log", "a", encoding="utf-8") as log:
        with contextlib.redirect_stdout(Tee(sys.stdout, log)), \
                contextlib.redirect_stderr(Tee(sys.stderr, log)):
            print(f"===== Daily pass {datetime.now():%Y-%m-%d %H:%M:%S} "
                  f"(snapshot date {today.isoformat()}) =====")
            code = run_pass(today, Path(lock_path or DEFAULT_LOCK), clock)
            print(f"Exit code {code}")
            return code


if __name__ == "__main__":
    sys.exit(main())
