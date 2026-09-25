#!/usr/bin/env python3
"""Rename functions and variables across every file of one Juliet group.

Anonymization by declaration site, not by name. Every function and variable
*declared inside the group's own files* is renamed; anything declared
elsewhere (malloc, free, printLine, std_testcase.h) keeps its name, because
the rule never looks at the name. main is the only exception inside the group.

Scope (decided in discussions_folder/discussion_personal_mac_1.md, S3):
functions, globals, locals and parameters only. NOT types, namespaces,
fields, macros, comments or string literals.

Goto labels are renamed too. The scope decision neither includes nor excludes
them -- they are not functions, variables or any of the listed exclusions --
but variant 18 writes `goto source;` and `sink:`, which names the source and
sink roles as plainly as badSink() did. They are declared inside the corpus,
so the declaration-site rule covers them. Identifier leaks therefore
remain by design -- class and namespace names in the C++ variants, the
"Calling bad()..." strings, the POTENTIAL FLAW comments -- and any leak
count must say so.

Names come from clang's own JSON AST, so every reference is already resolved
to its declaration: no regex, no textual matching. Rewrites happen by byte
offset, back to front, so offsets stay valid as we go.

New names are assigned from a seeded shuffle rather than in call-graph or
alphabetical order, so the number cannot be read as a hint about which
function is the vulnerable one.
"""

import argparse
import json
import random
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from juliet.groups import collect_groups

FUNC_KINDS = {"FunctionDecl"}
VAR_KINDS = {"VarDecl"}
PARM_KINDS = {"ParmVarDecl"}
# Methods, constructors and destructors are a known gap (variants 72-74,
# 81-84); they are counted and reported, never renamed.
METHOD_KINDS = {"CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl",
                "CXXConversionDecl"}
REF_KINDS = {"DeclRefExpr", "MemberExpr"}
LABEL_DECL_KIND = "LabelStmt"
LABEL_REF_KIND = "GotoStmt"

KEEP = {"main"}


def ast_json(src, includes):
    """Ask clang for the JSON AST of one file."""
    cmd = ["clang++" if src.suffix == ".cpp" else "clang",
           "-fsyntax-only", "-w", "-Xclang", "-ast-dump=json"]
    for inc in includes:
        cmd += ["-I", str(inc)]
    cmd.append(str(src))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError("clang failed on {}: {}".format(src, proc.stderr[:300]))
    return json.loads(proc.stdout)


class LocTracker:
    """Resolve clang's abbreviated source locations.

    clang prints a location field only when it differs from the previous one,
    so `file` is present on the first node of a file and then omitted until it
    changes. Resolving a location therefore means replaying the walk in
    document order and carrying the last value seen -- including through the
    spellingLoc/expansionLoc pairs of macro expansions, which must be visited
    in clang's own key order or the carried file goes wrong.
    """

    def __init__(self):
        self.file = None

    def resolve(self, loc):
        """Return (file, offset, tok_len, from_macro) or None."""
        if not isinstance(loc, dict):
            return None
        if "expansionLoc" in loc or "spellingLoc" in loc:
            # Keep the carried file correct by visiting both halves in clang's
            # own key order, then decline the site: a token that came out of a
            # macro cannot be rewritten in the source text, and macros are out
            # of scope anyway.
            for key in ("spellingLoc", "expansionLoc"):
                if key in loc:
                    self.resolve(loc[key])
            return None
        if "file" in loc:
            self.file = loc["file"]
        if "offset" not in loc:
            return None
        return (self.file, loc["offset"], loc.get("tokLen", 0), False)


def walk(node, tracker, visit, stack=()):
    """Depth-first walk in document order, resolving locations as we go.

    `stack` carries the enclosing node kinds, which is how a VarDecl inside a
    function body is told apart from one at file scope.
    """
    if not isinstance(node, dict):
        return
    # Declarations carry the identifier position in `loc`. Expression nodes
    # such as DeclRefExpr have `loc: null` and carry it in `range.begin`, so
    # the effective position is whichever of the two resolves.
    loc = tracker.resolve(node.get("loc"))
    begin = None
    if "range" in node and isinstance(node["range"], dict):
        begin = tracker.resolve(node["range"].get("begin"))
    visit(node, loc or begin, stack)
    inner = node.get("inner") or []
    if inner:
        child_stack = stack + (node.get("kind", ""),)
        for child in inner:
            walk(child, tracker, visit, child_stack)
    if "range" in node and isinstance(node["range"], dict):
        tracker.resolve(node["range"].get("end"))


def collect(group, includes):
    """Collect declarations and references for a whole group.

    Returns (decls, refs, stats) where decls maps clang decl id -> record and
    refs is a list of (file, offset, tok_len, decl_id).
    """
    own = {str(p.resolve()) for p in group.files}
    own |= {p.name for p in group.files}

    decls = {}          # id -> {kind, name, file, own, global, pos}
    sites = []          # (file, offset, tok_len, id)
    param_pos = {}      # ParmVarDecl id -> index in its function
    stats = defaultdict(int)

    inc = list(includes) + [p.parent for p in group.headers]

    for src in group.sources:
        tree = ast_json(src, inc)
        tracker = LocTracker()
        tracker.file = str(src.resolve())

        def visit(node, loc, stack, _src=src):
            kind = node.get("kind")
            nid = node.get("id")

            if kind in METHOD_KINDS:
                stats["methods_skipped"] += 1
                return

            # A label declares itself where it appears; `goto` names it again
            # at the END of its range (the range begins at the goto keyword).
            if kind == LABEL_DECL_KIND and node.get("declId") and node.get("name"):
                if loc:
                    f, off, tok, _ = loc
                    name = node["name"]
                    in_group = Path(f).name in own or f in own
                    if node["declId"] not in decls:
                        decls[node["declId"]] = dict(
                            kind=LABEL_DECL_KIND, name=name, file=f,
                            own=in_group, pos=None)
                    if in_group and tok == len(name):
                        sites.append((f, off, tok, node["declId"]))
                return

            if kind == LABEL_REF_KIND and node.get("targetLabelDeclId"):
                end = ((node.get("range") or {}).get("end")) or {}
                rid = node["targetLabelDeclId"]
                if loc and "offset" in end:
                    sites.append((loc[0], end["offset"], end.get("tokLen", 0), rid))
                return

            if kind in FUNC_KINDS:
                params = [c for c in (node.get("inner") or [])
                          if (c or {}).get("kind") == "ParmVarDecl"]
                for i, prm in enumerate(params):
                    param_pos[prm.get("id")] = i

            if kind in FUNC_KINDS | VAR_KINDS | PARM_KINDS:
                name = node.get("name")
                if not name or not loc:
                    return
                f, off, tok, _ = loc
                in_group = Path(f).name in own or f in own
                if nid not in decls:
                    at_file_scope = not any(
                        k in ("FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl",
                              "CXXDestructorDecl") for k in stack)
                    decls[nid] = dict(kind=kind, name=name, file=f, own=in_group,
                                      pos=param_pos.get(nid),
                                      **{"global": kind in VAR_KINDS and at_file_scope})
                if in_group and tok == len(name):
                    sites.append((f, off, tok, nid))
                return

            if kind in REF_KINDS:
                ref = node.get("referencedDecl") or {}
                rid = ref.get("id")
                name = ref.get("name")
                if not rid or not name or not loc:
                    return
                f, off, tok, _ = loc
                if tok != len(name):
                    return
                if rid not in decls:
                    decls[rid] = dict(kind=ref.get("kind", ""), name=name,
                                      file=None, own=False, pos=None)
                sites.append((f, off, tok, rid))

        walk(tree, tracker, visit)

    return decls, sites, stats


def build_map(decls, seed):
    """One group-wide name map. Cross-file symbols join by name, the way the
    linker joins them, so an extern declaration and its definition agree."""
    by_kind = defaultdict(set)
    for rec in decls.values():
        if not rec["own"] or rec["name"] in KEEP:
            continue
        if rec["kind"] in FUNC_KINDS:
            by_kind["fn"].add(rec["name"])
        elif rec["kind"] in VAR_KINDS:
            by_kind["gv" if rec.get("global") else "lv"].add(rec["name"])
        elif rec["kind"] == LABEL_DECL_KIND:
            by_kind["lb"].add(rec["name"])
        elif rec["kind"] in PARM_KINDS:
            continue   # handled by position, see kind_prefix/rewrite

    mapping = {}
    rng = random.Random(seed)
    for prefix, names in by_kind.items():
        ordered = sorted(names)
        numbers = list(range(len(ordered)))
        rng.shuffle(numbers)          # the number must not encode the order
        for name, n in zip(ordered, numbers):
            mapping[(prefix, name)] = "{}_{}".format(prefix, n)
    return mapping


def kind_prefix(rec):
    if rec["kind"] in FUNC_KINDS:
        return "fn"
    if rec["kind"] in VAR_KINDS:
        return "gv" if rec.get("global") else "lv"
    if rec["kind"] == LABEL_DECL_KIND:
        return "lb"
    return None


def new_name(rec, mapping):
    """The replacement for one declaration, or None to leave it alone."""
    if not rec["own"] or rec["name"] in KEEP:
        return None
    if rec["kind"] in PARM_KINDS:
        # By position: clang lets a prototype and a definition give the same
        # parameter different names, and renaming by name would split them.
        pos = rec.get("pos")
        return None if pos is None else "pm_{}".format(pos)
    prefix = kind_prefix(rec)
    return mapping.get((prefix, rec["name"])) if prefix else None


def rewrite(group, decls, sites, mapping, out_dir):
    """Apply the map by byte offset, back to front."""
    edits = defaultdict(list)
    for f, off, tok, nid in sites:
        rec = decls.get(nid)
        if not rec:
            continue
        new = new_name(rec, mapping)
        if new:
            edits[Path(f).name].append((off, tok, new))

    out_dir.mkdir(parents=True, exist_ok=True)
    written = {}
    for path in group.files:
        data = path.read_bytes()
        for off, tok, new in sorted(edits.get(path.name, []), reverse=True):
            data = data[:off] + new.encode() + data[off + tok:]
        dest = out_dir / path.name
        dest.write_bytes(data)
        written[path.name] = dest
    return written, sum(len(v) for v in edits.values())


def call_graph(group, includes):
    """Caller -> set of callees, over functions defined in the group.

    Functions merely *declared* in the group (prototypes) or pulled in from a
    header are not nodes: an inline helper from std_testcase.h is not part of
    the test case's own call structure. Indirect calls through a function
    pointer appear as <INDIRECT> -- variant 65 needs points-to analysis to
    resolve them, which this does not do.
    """
    inc = list(includes) + [p.parent for p in group.headers]
    own = {p.name for p in group.files}
    graph = defaultdict(set)
    defined = set()

    for src in group.sources:
        tree = ast_json(src, inc)
        tracker = LocTracker()
        tracker.file = str(src.resolve())
        current = []

        def visit(node, loc, stack):
            kind = node.get("kind")
            if kind in FUNC_KINDS and node.get("name"):
                has_body = any((c or {}).get("kind") == "CompoundStmt"
                               for c in (node.get("inner") or []))
                if has_body and loc and Path(loc[0]).name in own:
                    defined.add(node["name"])
                    current.append(node["name"])
                    graph[node["name"]]
            if kind == "CallExpr" and current:
                callee = None
                for child in (node.get("inner") or []):
                    if (child or {}).get("kind") == "ImplicitCastExpr":
                        for gc in (child.get("inner") or []):
                            ref = (gc or {}).get("referencedDecl") or {}
                            if (gc or {}).get("kind") == "DeclRefExpr" and ref.get("name"):
                                callee = ref["name"]
                    ref = (child or {}).get("referencedDecl") or {}
                    if (child or {}).get("kind") == "DeclRefExpr" and ref.get("name"):
                        callee = callee or ref["name"]
                graph[current[-1]].add(callee or "<INDIRECT>")

        walk(tree, tracker, visit)

    # Builtins such as __builtin_object_size (from memset) and anything
    # declared outside the group are not part of the test case's call graph.
    return {f: {c for c in cs if c in defined or c == "<INDIRECT>"}
            for f, cs in graph.items() if f in defined}


def validate(group, out_dir, includes, mapping, decls):
    """Three checks: it still compiles, the line count is unchanged, and the
    call graph of the renamed code is isomorphic to the original under the
    mapping."""
    results = {}

    renamed = Group_like(group, out_dir)
    ok = True
    for src in renamed.sources:
        cmd = ["clang++" if src.suffix == ".cpp" else "clang",
               "-fsyntax-only", "-w"]
        for i in list(includes) + [p.parent for p in renamed.headers]:
            cmd += ["-I", str(i)]
        cmd.append(str(src))
        if subprocess.run(cmd, capture_output=True).returncode != 0:
            ok = False
    results["COMPILES"] = ok

    results["SAME_LINES"] = all(
        len((out_dir / p.name).read_bytes().splitlines()) == len(p.read_bytes().splitlines())
        for p in group.files)

    if not ok:
        results["CALLGRAPH_ISO"] = None
        return results

    before = call_graph(group, includes)
    after = call_graph(renamed, includes)
    fn = {n: mapping.get(("fn", n), n) for n in before}
    expected = {fn.get(f, f): {fn.get(c, c) for c in cs} for f, cs in before.items()}
    results["CALLGRAPH_ISO"] = expected == after
    if expected != after:
        results["_diff"] = (expected, after)
    return results


class Group_like:
    """A Group whose files live in the renamed output directory."""

    def __init__(self, group, out_dir):
        self.name = group.name
        self.label = group.label
        self.sources = [out_dir / p.name for p in group.sources]
        self.headers = [out_dir / p.name for p in group.headers]

    @property
    def files(self):
        return self.headers + self.sources


def rename_group(group, includes, out_dir, seed):
    decls, sites, stats = collect(group, includes)
    mapping = build_map(decls, seed)
    written, n_edits = rewrite(group, decls, sites, mapping, out_dir)
    checks = validate(group, out_dir, includes, mapping, decls)
    return mapping, n_edits, checks, stats


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source_dir")
    ap.add_argument("-I", dest="includes", action="append", default=[])
    ap.add_argument("--header-dir", action="append", default=[])
    ap.add_argument("--out", required=True, help="output directory for renamed code")
    ap.add_argument("--group", action="append", help="rename only these groups")
    ap.add_argument("--limit", type=int)
    ap.add_argument("--seed", type=int, default=20260921)
    ap.add_argument("--show", action="store_true", help="print the name map")
    ap.add_argument("--jobs", type=int, default=8)
    args = ap.parse_args()

    groups, _ = collect_groups(args.source_dir, args.header_dir)
    names = args.group or sorted(groups)
    if args.limit:
        names = names[:args.limit]

    out_root = Path(args.out)
    failures, totals = [], defaultdict(int)

    missing = [n for n in names if n not in groups]
    if missing:
        sys.exit("no such group: " + missing[0])

    def run(name):
        try:
            return name, rename_group(groups[name], args.includes,
                                      out_root / name, args.seed), None
        except Exception as exc:
            return name, None, exc

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        outcomes = list(pool.map(run, names))

    for name, payload, exc in outcomes:
        if exc is not None:
            failures.append((name, "ERROR: {}".format(exc)))
            continue
        mapping, n_edits, checks, stats = payload
        group = groups[name]

        bad = [k for k, v in checks.items() if not k.startswith("_") and v is not True]
        totals["groups"] += 1
        totals["edits"] += n_edits
        totals["methods_skipped"] += stats.get("methods_skipped", 0)
        if bad:
            failures.append((name, ",".join(bad)))
        if args.show:
            print("\n== {} ({}) {} edits, {} names".format(
                name, group.label, n_edits, len(mapping)))
            for (prefix, old), new in sorted(mapping.items()):
                print("   {:40s} -> {}".format(old, new))
            print("   checks:", checks)

    print("\n{} groups renamed, {} identifier sites rewritten".format(
        totals["groups"], totals["edits"]))
    if totals["methods_skipped"]:
        print("  C++ methods left unrenamed (known gap): {}".format(
            totals["methods_skipped"]))
    if failures:
        print("  {} groups failed validation:".format(len(failures)))
        for name, why in failures[:15]:
            print("    {:55s} {}".format(name, why))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
