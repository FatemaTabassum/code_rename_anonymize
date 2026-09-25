"""Step 2: gate each step-1 group before it goes downstream.

This is a checkpoint, not a transform. It compiles every piece of a group
(a directory produced by step_1_grouping.write_groups) on its own and reads
the symbol table with nm, then checks that the pieces really do form one
complete, consistent test case.

    COMPILES     every piece compiles on its own
    CLOSED       every needed project symbol is defined by some piece
    NO_DUP_DEF   no project symbol is strongly defined by two pieces
    CONNECTED    pieces defining project symbols form one have/need chain
    ONE_MAIN     at most one piece defines main

A group's headers are expected to already sit next to its pieces (step 1
copies them in), so no extra include path is needed for local `#include
"X.h"`; `includes` is only for shared headers like std_testcase.h.
"""
import argparse
import platform
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Mach-O (macOS) nm prepends an extra leading underscore to every global
# symbol name (main -> _main, _ZTV... -> __ZTV...) that ELF/Linux nm does
# not; strip it so the checks below see the same bare names on both.
_STRIP_LEADING_UNDERSCORE = platform.system() == "Darwin"

# Compiler-generated C++ symbols (typeinfo, vtable, ...) are legitimately
# defined more than once in a group and must not count as duplicates.
GENERATED_RE = re.compile(r"^_Z(TI|TS|TV|TT|TC)")

# A symbol belongs to the test case (rather than libc) if the CWE id
# survives in its name.
PROJECT_RE = re.compile(r"CWE\d")

CHECKS = ("COMPILES", "CLOSED", "NO_DUP_DEF", "CONNECTED", "ONE_MAIN")


def is_project(sym: str) -> bool:
    """Test-case symbol, excluding anything the compiler generated."""
    return bool(PROJECT_RE.search(sym)) and not GENERATED_RE.match(sym)


def is_project_linkage(sym: str) -> bool:
    """Test-case symbol, including compiler-generated vtables and typeinfo.

    Variants 81-84 link their driver to their sink only through the vtable:
    the driver builds a subclass and calls a method through a base
    reference, so the call is virtual and never names the sink's symbol
    directly. Excluding vtable/typeinfo from CONNECTED would make every one
    of those groups look unlinked, so CONNECTED uses this wide set while
    CLOSED and NO_DUP_DEF use the strict is_project() set.
    """
    return bool(PROJECT_RE.search(sym))


def _demangled_name(sym: str) -> str:
    if _STRIP_LEADING_UNDERSCORE and sym.startswith("_"):
        return sym[1:]
    return sym


def read_symbols(obj_path: Path) -> tuple[set[tuple[str, str]], set[str]]:
    """Return (defined, needed) symbol-name sets for one object file."""
    out = subprocess.run(
        ["nm", "--defined-only", "-g", str(obj_path)],
        capture_output=True, text=True,
    )
    defined = set()
    for line in out.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            defined.add((_demangled_name(parts[-1]), parts[-2]))

    out = subprocess.run(["nm", "-u", str(obj_path)], capture_output=True, text=True)
    needed = {_demangled_name(line.split()[-1]) for line in out.stdout.splitlines() if line.split()}
    return defined, needed


def compile_piece(src: Path, includes: list[Path], obj_dir: Path) -> tuple[Path | None, str]:
    """Compile one piece with clang. Returns (object path or None, stderr)."""
    obj = obj_dir / (src.stem + ".o")
    cmd = ["clang++" if src.suffix == ".cpp" else "clang", "-c", "-w", "-o", str(obj)]
    for inc in includes:
        cmd += ["-I", str(inc)]
    cmd.append(str(src))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return (obj if proc.returncode == 0 else None), proc.stderr


def check_group(group_dir: Path, includes: list[Path], obj_dir: Path) -> dict:
    """Run every check on one step-1 group directory. Returns a result dict."""
    sources = sorted(p for p in group_dir.iterdir() if p.suffix in (".c", ".cpp"))
    res = {c: True for c in CHECKS}
    res.update(group=group_dir.name, notes=[], empty=[], pieces=len(sources))

    haves: dict[str, set[str]] = {}
    needs: dict[str, set[str]] = {}
    haves_link: dict[str, set[str]] = {}
    needs_link: dict[str, set[str]] = {}
    mains: list[str] = []

    for src in sources:
        obj, stderr = compile_piece(src, includes, obj_dir)
        if obj is None:
            res["COMPILES"] = False
            first = next((l for l in stderr.splitlines() if ": error:" in l), stderr[:200])
            res["notes"].append(f"{src.name}: {first.strip()}")
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
            res[c] = None
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
    # under the have/need relation. Edges use the wide (linkage) symbol set
    # so vtable-only connections (variants 81-84) still count.
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


def gate_groups(groups_root: Path, includes: list[Path], obj_root: Path, jobs: int = 8) -> list[dict]:
    """Run check_group on every <omit_type>/<group>/ directory under groups_root."""
    group_dirs = [
        d for omit_dir in sorted(groups_root.iterdir()) if omit_dir.is_dir()
        for d in sorted(omit_dir.iterdir()) if d.is_dir()
    ]

    def run(group_dir: Path) -> dict:
        rel = f"{group_dir.parent.name}/{group_dir.name}"
        obj_dir = obj_root / rel
        obj_dir.mkdir(parents=True, exist_ok=True)
        res = check_group(group_dir, includes, obj_dir)
        res["group"] = rel
        return res

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        return list(pool.map(run, group_dirs))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("groups_root", help="e.g. outputs/step_1/CWE415_groups")
    ap.add_argument("-I", dest="includes", action="append", default=[])
    ap.add_argument("--cache", help="directory for object files (default: a temp dir)")
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    tmp = None
    if args.cache:
        obj_root = Path(args.cache)
        obj_root.mkdir(parents=True, exist_ok=True)
    else:
        tmp = tempfile.TemporaryDirectory()
        obj_root = Path(tmp.name)

    results = gate_groups(Path(args.groups_root), [Path(i) for i in args.includes], obj_root, args.jobs)

    failed = [r for r in results if any(r[c] is not True for c in CHECKS)]
    for r in failed[:20]:
        bad = [c for c in CHECKS if r[c] is not True]
        print("FAIL {:60s} {}".format(r["group"], ",".join(bad)))
        for note in r["notes"][:2]:
            print("       " + note)

    print(f"\n{len(results)} groups: {len(results) - len(failed)} PASS, {len(failed)} FAIL")
    print(f"  groups without main: {sum(1 for r in results if r.get('no_main'))}")
    if tmp:
        tmp.cleanup()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
