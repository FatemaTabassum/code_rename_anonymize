"""
Gate script: check that each Juliet test-case group is complete and self-consistent
BEFORE merging / renaming / graph extraction.

Groups come from merge_c.group_by_variant (filename rule). For every group, each piece is
compiled to an object file and its symbols are read with `nm`:
    "I have"  = symbols the piece defines
    "I need"  = symbols the piece uses but does not define

Checks (FAIL = the group must not go downstream):
    COMPILES     every piece compiles on its own
    CLOSED       every needed project symbol (name contains "CWE") is defined by another piece
    NO_DUP_DEF   no project symbol is defined (strongly) by two pieces
    CONNECTED    all pieces that define a project symbol form ONE chain of have/need links
    ONE_MAIN     at most one piece defines main()
Reported but not failing:
    EMPTY        pieces that define nothing (e.g. 81_bad in an omitbad sample)
    NO_MAIN      no main() in the group

Usage:
    python3 check_group.py <source-dir> [-I include_dir ...] [--cache obj_dir] [--group NAME]
Exit status is 1 if any group fails.
"""

import argparse
import re
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from merge_c import group_by_variant

DEFINED = set("TDBSRGCWVIA")   # nm type letters that mean "defined here"
WEAK = set("WVC")              # weak / common: several pieces may legitimately define these
# compiler-generated C++ data (vtable, typeinfo, typeinfo name, VTT, guard variable) may legitimately
# appear in several pieces
GENERATED_RE = re.compile(r"^_{1,2}Z(TV|TI|TS|TT|GV)")


def is_project(sym: str) -> bool:
    return "CWE" in sym


def read_symbols(src: Path, includes: list[Path], cache: Path) -> tuple[bool, str, dict, set]:
    """Compile one piece; return (ok, error, {defined symbol: nm type}, {undefined symbols})."""
    obj = cache / f"{src.parent.parent.name}__{src.name}.o"
    if not obj.exists():
        cmd = ["clang", "-c", "-w", *[f"-I{i}" for i in includes], f"-I{src.parent}", str(src), "-o", str(obj)]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode:
            return False, (r.stderr.strip().splitlines() or ["compile error"])[0], {}, set()
    out = subprocess.run(["nm", "-g", str(obj)], capture_output=True, text=True).stdout
    have: dict[str, str] = {}
    need: set[str] = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) == 2 and p[0] == "U":
            need.add(p[1])
        elif len(p) == 3 and p[1] in DEFINED:
            have[p[2]] = p[1]
    return True, "", have, need


def check_group(name: str, files: list[Path], includes: list[Path], cache: Path) -> tuple[list[str], list[str]]:
    fails: list[str] = []
    notes: list[str] = []
    info = {f: read_symbols(f, includes, cache) for f in files}

    for f, (ok, err, _, _) in info.items():
        if not ok:
            fails.append(f"COMPILES: {f.name}: {err}")
    if fails:
        return fails, notes
    have = {f: v[2] for f, v in info.items()}
    need = {f: v[3] for f, v in info.items()}

    definers: dict[str, list[Path]] = defaultdict(list)
    for f, syms in have.items():
        for s in syms:
            definers[s].append(f)

    # CLOSED: needed project symbols must be defined somewhere in the group
    for f in files:
        for s in sorted(need[f]):
            if is_project(s) and s not in definers:
                fails.append(f"CLOSED: {f.name} needs '{s}' but no piece in the group defines it")

    # NO_DUP_DEF: strong duplicate definitions would clash when linked or merged
    for s, fs in definers.items():
        if len(fs) > 1 and is_project(s):
            if any(have[f][s] not in WEAK for f in fs) and not GENERATED_RE.match(s):
                fails.append(f"NO_DUP_DEF: '{s}' defined in {sorted(f.name for f in fs)}")

    # CONNECTED: pieces that define project symbols must form one component
    real = [f for f in files if any(is_project(s) for s in have[f])]
    parent = {f: f for f in real}

    def find(x: Path) -> Path:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for f in real:
        for s in need[f]:
            for g in definers.get(s, []):
                if g in parent and is_project(s):
                    parent[find(f)] = find(g)
    comps = {find(f) for f in real}
    if len(comps) > 1:
        parts = defaultdict(list)
        for f in real:
            parts[find(f)].append(f.name.split("_")[-2])
        fails.append(f"CONNECTED: {len(comps)} separate chains: {sorted(map(sorted, parts.values()))}")

    mains = [f for f in files if "_main" in have[f] or "main" in have[f]]
    if len(mains) > 1:
        fails.append(f"ONE_MAIN: main() defined in {sorted(f.name for f in mains)}")
    elif not mains:
        notes.append("NO_MAIN")
    empty = [f.name for f in files if not any(s not in ("_main", "main") for s in have[f])]
    if empty:
        notes.append(f"EMPTY x{len(empty)}")
    return fails, notes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("source_dir", type=Path)
    ap.add_argument("-I", dest="includes", action="append", default=[], type=Path)
    ap.add_argument("--cache", type=Path, default=Path("/tmp/check_group_obj"))
    ap.add_argument("--group", default=None, help="only groups whose merged name contains this text")
    a = ap.parse_args()
    a.cache.mkdir(parents=True, exist_ok=True)

    groups = {n: fs for n, fs in group_by_variant(a.source_dir).items() if not a.group or a.group in n}
    with ThreadPoolExecutor(8) as ex:
        results = dict(zip(groups, ex.map(lambda kv: check_group(kv[0], kv[1], a.includes, a.cache), groups.items())))

    bad = 0
    for name, (fails, notes) in sorted(results.items()):
        if fails:
            bad += 1
            print(f"[FAIL] {name}")
            for m in fails:
                print(f"         {m}")
        elif a.group:
            print(f"[PASS] {name}  {' '.join(notes)}")
    print(f"\n{len(groups) - bad} pass, {bad} fail, of {len(groups)} groups")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
