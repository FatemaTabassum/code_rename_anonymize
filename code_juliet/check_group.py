#!/usr/bin/env python3
"""Gate: answer PASS/FAIL for one Juliet group before it goes downstream.

This is a checkpoint, not a transform. It compiles every piece of a group on
its own and reads the symbol table with nm, then checks that the pieces really
do form one complete, consistent test case.

    COMPILES     every piece compiles on its own
    CLOSED       every needed project symbol is defined by some piece
    NO_DUP_DEF   no project symbol is strongly defined by two pieces
    CONNECTED    pieces defining project symbols form one have/need chain
    ONE_MAIN     at most one piece defines main

EMPTY and NO_MAIN are reported but never fail a group: the omit preprocessing
legitimately empties pieces, and a sink piece has no main.

A pass means the group is complete and consistent. It says nothing about
renaming or any later stage.

Usage:
    check_group.py <source-dir> [-I include_dir ...] [--cache obj_dir]
                   [--group NAME] [--jobs N]
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from juliet.groups import collect_groups

# Compiler-generated C++ symbols: typeinfo, typeinfo name, vtable, VTT,
# construction vtable. Emitted into every translation unit that uses the
# class, so they are legitimately defined more than once in a group and must
# not count as duplicate definitions.
#
# They are still real linkage, though, and in variants 81-84 they are the
# ONLY linkage. The 81a driver builds a subclass and calls action() through
# a base reference; the call is virtual and the constructor is implicit, so
# the sink piece is never referenced by name. The single undefined project
# symbol in 81a is the subclass vtable. Connectivity therefore uses the wide
# symbol set, while CLOSED and NO_DUP_DEF use the strict one.
GENERATED_RE = re.compile(r"^_Z(TI|TS|TV|TT|TC)")

# A symbol belongs to the test case (rather than libc) if the CWE id survives
# in its name -- directly in C, or through the namespace in a C++ mangling.
PROJECT_RE = re.compile(r"CWE\d")

CHECKS = ("COMPILES", "CLOSED", "NO_DUP_DEF", "CONNECTED", "ONE_MAIN")


def is_project(sym):
    """Test-case symbol, excluding anything the compiler generated."""
    return bool(PROJECT_RE.search(sym)) and not GENERATED_RE.match(sym)


def is_project_linkage(sym):
    """Test-case symbol, including vtables and typeinfo."""
    return bool(PROJECT_RE.search(sym))


def read_symbols(obj_path):
    """Return (defined, needed) symbol-name sets for one object file."""
    out = subprocess.run(
        ["nm", "--defined-only", "-g", str(obj_path)],
        capture_output=True, text=True,
    )
    defined = set()
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            # 'C' is a common symbol -- an uninitialized global. It counts as
            # a definition; treating it as undefined falsely flags variant 68.
            defined.add((parts[-1], parts[-2]))

    out = subprocess.run(["nm", "-u", str(obj_path)], capture_output=True, text=True)
    needed = {line.split()[-1] for line in out.stdout.splitlines() if line.split()}
    return defined, needed


def compile_piece(src, includes, obj_dir):
    obj = obj_dir / (src.stem + ".o")
    cmd = ["clang++" if src.suffix == ".cpp" else "clang", "-c", "-w", "-o", str(obj)]
    for inc in includes:
        cmd += ["-I", str(inc)]
    cmd.append(str(src))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return (obj if proc.returncode == 0 else None), proc.stderr


def check_group(group, includes, obj_dir):
    """Run every check on one group. Returns a result dict."""
    res = {c: True for c in CHECKS}
    res.update(group=group.name, label=group.label, notes=[],
               empty=[], pieces=len(group.sources))

    inc = list(includes) + [p.parent for p in group.headers]
    haves, needs, mains = {}, {}, []
    haves_link, needs_link = {}, {}

    for src in group.sources:
        obj, stderr = compile_piece(src, inc, obj_dir)
        if obj is None:
            res["COMPILES"] = False
            first = next((l for l in stderr.splitlines() if ": error:" in l), stderr[:200])
            res["notes"].append("{}: {}".format(src.name, first.strip()))
            continue

        defined, needed = read_symbols(obj)
        strong = {n for n, t in defined if t not in ("W", "V", "w", "v")}
        if any(n == "main" for n, _ in defined):
            mains.append(src.name)
        proj_def = {n for n in strong if is_project(n)}
        haves[src.name] = proj_def
        needs[src.name] = {n for n in needed if is_project(n)}
        haves_link[src.name] = {n for n in strong if is_project_linkage(n)}
        needs_link[src.name] = {n for n in needed if is_project_linkage(n)}
        if not proj_def and not any(n == "main" for n, _ in defined):
            res["empty"].append(src.name)

    if not res["COMPILES"]:
        for c in ("CLOSED", "NO_DUP_DEF", "CONNECTED", "ONE_MAIN"):
            res[c] = None  # undetermined
        return res

    all_defined = set().union(*haves.values()) if haves else set()
    missing = set().union(*needs.values()) - all_defined if needs else set()
    if missing:
        res["CLOSED"] = False
        res["notes"].append("undefined: " + ", ".join(sorted(missing)[:3]))

    seen, dups = set(), set()
    for defs in haves.values():
        dups |= seen & defs
        seen |= defs
    if dups:
        res["NO_DUP_DEF"] = False
        res["notes"].append("defined twice: " + ", ".join(sorted(dups)[:3]))

    if len(mains) > 1:
        res["ONE_MAIN"] = False
        res["notes"].append("main in: " + ", ".join(mains))
    res["no_main"] = not mains

    # Pieces that define project symbols must form one connected component
    # under the have/need relation. Pieces emptied by the omit preprocessing
    # define nothing and cannot be linked to, so they are excluded.
    nodes = [f for f in haves if haves[f]]
    if len(nodes) > 1:
        adj = {f: set() for f in nodes}
        for a in nodes:
            for b in nodes:
                if a != b and (needs_link[a] & haves_link[b]):
                    adj[a].add(b)
                    adj[b].add(a)
        stack, reached = [nodes[0]], {nodes[0]}
        while stack:
            for nxt in adj[stack.pop()] - reached:
                reached.add(nxt)
                stack.append(nxt)
        if len(reached) != len(nodes):
            res["CONNECTED"] = False
            res["notes"].append("unlinked: " + ", ".join(sorted(set(nodes) - reached)[:3]))

    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source_dir")
    ap.add_argument("-I", dest="includes", action="append", default=[])
    ap.add_argument("--header-dir", action="append", default=[])
    ap.add_argument("--cache", help="directory for object files (default: a temp dir)")
    ap.add_argument("--group", help="check only this group")
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    groups, unmatched = collect_groups(args.source_dir, args.header_dir)
    if unmatched:
        print("warning: {} files did not match the naming rule".format(len(unmatched)),
              file=sys.stderr)
    if args.group:
        groups = {k: v for k, v in groups.items() if k == args.group}
        if not groups:
            sys.exit("no such group: " + args.group)

    import tempfile
    from concurrent.futures import ThreadPoolExecutor

    tmp = None
    if args.cache:
        obj_root = Path(args.cache)
        obj_root.mkdir(parents=True, exist_ok=True)
    else:
        tmp = tempfile.TemporaryDirectory()
        obj_root = Path(tmp.name)

    def run(item):
        name, group = item
        d = obj_root / name
        d.mkdir(parents=True, exist_ok=True)
        return check_group(group, args.includes, d)

    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        results = list(pool.map(run, sorted(groups.items())))

    failed = [r for r in results if any(r[c] is not True for c in CHECKS)]
    for r in failed[:20]:
        bad = [c for c in CHECKS if r[c] is not True]
        print("FAIL {:60s} {}".format(r["group"], ",".join(bad)))
        for note in r["notes"][:2]:
            print("       " + note)

    print("\n{} groups: {} PASS, {} FAIL".format(
        len(results), len(results) - len(failed), len(failed)))
    print("  pieces emptied by omit preprocessing: {}".format(
        sum(len(r["empty"]) for r in results)))
    print("  groups without main: {}".format(sum(1 for r in results if r.get("no_main"))))
    if tmp:
        tmp.cleanup()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
