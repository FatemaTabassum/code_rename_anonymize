"""Run a command and record it in runs/runs.jsonl, so every experiment leaves a trace.

Usage (from the repo root):

    uv run python track.py [--note "why I ran this"] -- <command> [args...]

    uv run python track.py --note "gate on CWE415" -- \
        uv run python liza/prompt_pipeline/src/step_2_gate.py ...

Each run appends one JSON line (time, command, code version, exit code,
duration, note, last lines of output) to runs/runs.jsonl and saves the full
output to runs/logs/<run_id>.log. Output is also shown live in the terminal.

    uv run python track.py --last 5     # show the last 5 runs
"""
import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List

ROOT = Path(__file__).resolve().parent
RUNS_DIR = ROOT / "runs"
RUNS_FILE = RUNS_DIR / "runs.jsonl"
TAIL_LINES = 15


def _git(*args: str) -> str:
    """Return stripped git output, or '' when git is unavailable."""
    try:
        out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)
    except FileNotFoundError:
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def run(cmd: List[str], note: str) -> int:
    """Run `cmd`, stream its output, and append a record to runs.jsonl."""
    run_id = datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = RUNS_DIR / "logs" / f"{run_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    start = time.time()
    lines: List[str] = []
    with open(log_path, "w") as log:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        assert proc.stdout is not None
        for line in proc.stdout:
            sys.stdout.write(line)
            log.write(line)
            lines.append(line.rstrip("\n"))
        code = proc.wait()

    record = {
        "run_id": run_id,
        "cmd": " ".join(cmd),
        "cwd": str(Path.cwd()),
        "note": note,
        "commit": _git("rev-parse", "--short", "HEAD"),
        "uncommitted_changes": bool(_git("status", "--porcelain")),
        "exit_code": code,
        "seconds": round(time.time() - start, 1),
        "tail": lines[-TAIL_LINES:],
        "log": str(log_path.relative_to(ROOT)),
    }
    with open(RUNS_FILE, "a") as f:
        f.write(json.dumps(record) + "\n")
    status = "OK" if code == 0 else f"FAILED (exit {code})"
    print(f"\n[track] run {run_id} {status}, logged to {RUNS_FILE.relative_to(ROOT)}", file=sys.stderr)
    return code


def show_last(n: int) -> None:
    """Print a one-line summary of the last `n` runs."""
    if not RUNS_FILE.exists():
        print("No runs recorded yet.")
        return
    records = [json.loads(l) for l in RUNS_FILE.read_text().splitlines() if l.strip()]
    for r in records[-n:]:
        status = "ok " if r["exit_code"] == 0 else "ERR"
        dirty = "+changes" if r["uncommitted_changes"] else ""
        note = f"  # {r['note']}" if r["note"] else ""
        print(f"{r['run_id']} {status} {r['seconds']:>7}s  code {r['commit'] or '-'}{dirty}  {r['cmd']}{note}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--note", default="", help="one line on why you ran this")
    parser.add_argument("--last", type=int, metavar="N", help="show the last N runs and exit")
    parser.add_argument("cmd", nargs=argparse.REMAINDER, help="command to run, after --")
    args = parser.parse_args()

    if args.last:
        show_last(args.last)
        return 0
    cmd = args.cmd[1:] if args.cmd[:1] == ["--"] else args.cmd
    if not cmd:
        parser.error("give a command to run after --")
    return run(cmd, args.note)


if __name__ == "__main__":
    sys.exit(main())
