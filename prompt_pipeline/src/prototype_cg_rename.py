"""Prototype: group call graph + binding-based renaming via clang JSON AST (no LLVM)."""
import json, subprocess, sys, re, random
from pathlib import Path
from collections import defaultdict

INC = sys.argv[1]; FILES = [Path(p) for p in sys.argv[2:]]
KEEP = {"main"}; SEED = 1234

def ast(path):
    out = subprocess.run(["clang","-fsyntax-only","-w","-Xclang","-ast-dump=json","-I",INC,str(path)],
                         capture_output=True,text=True,check=True).stdout
    return json.loads(out)

def walk(node, mine, st, fn, visit):
    """document-order walk; clang omits 'file' unless it changed, so track it."""
    for k in ("loc","range"):
        v = node.get(k)
        if not v: continue
        for loc in ([v] if k=="loc" else [v.get("begin",{}), v.get("end",{})]):
            for key in loc:                      # follow clang's own print order
                sub = loc[key] if key in ("spellingLoc","expansionLoc") else None
                if key == "file": st["file"] = loc["file"]
                if sub and "file" in sub: st["file"] = sub["file"]
    kind = node.get("kind")
    if kind == "FunctionDecl":
        fn = node.get("name")
    visit(node, st["file"], fn)
    for c in node.get("inner", []):
        walk(c, mine, st, fn, visit)

PC=[0]
def analyse(path):
    tu = ast(path); rows = {"decl":[], "ref":[], "call":[], "addr":[]}
    mine = str(path)
    def visit(n, f, fn):
        k = n.get("kind"); same = (f == mine)
        if k in ("FunctionDecl","VarDecl","ParmVarDecl") and same and "name" in n and "loc" in n:
            loc = n["loc"]; loc = loc.get("spellingLoc", loc)
            if "offset" in loc and "includedFrom" not in loc:
                if k == "FunctionDecl": PC[0] = 0
                if k == "ParmVarDecl": PC[0] += 1
                rows["decl"].append((k, n["id"], n["name"], PC[0] if k=="ParmVarDecl" else n.get("storageClass"), loc["offset"], loc["tokLen"], fn,
                                     "mangledName" in n))
        if k == "DeclRefExpr" and same:
            d = n["referencedDecl"]; loc = n["range"]["begin"]; loc = loc.get("spellingLoc", loc)
            if "offset" in loc: rows["ref"].append((d["kind"], d["id"], d["name"], loc["offset"], loc["tokLen"], fn, loc["line"] if "line" in loc else None))
    st = {"file": None}
    walk(tu, mine, st, None, visit)
    return rows, tu

def main():
    G = {}; calls = []; per = {}
    for p in FILES:
        rows, _ = analyse(p); per[p] = rows
    # ---- 1. group call graph (nodes = functions defined in group; edges from callee-position refs)
    defined = {d[2] for r in per.values() for d in r["decl"] if d[0]=="FunctionDecl"}
    # a ref in callee position vs address-taken: decide via 2nd pass over AST
    edges = set(); addr_taken = set()
    for p in FILES:
        _, tu = analyse(p)
        def visit(n, f, fn):
            if n.get("kind") == "CallExpr" and fn in defined:
                callee = n["inner"][0]
                while callee.get("kind") in ("ImplicitCastExpr","ParenExpr"): callee = callee["inner"][0]
                if callee.get("kind") == "DeclRefExpr" and callee["referencedDecl"]["kind"] == "FunctionDecl":
                    edges.add((fn, callee["referencedDecl"]["name"]))
                else:
                    edges.add((fn, "<INDIRECT>"))
        walk(tu, str(p), {"file":None}, None, visit)
    project = lambda n: n in defined
    print("CALL GRAPH (project functions + external callees):")
    for a,b in sorted(edges):
        print(f"  {a.split('char_')[-1] if 'char_' in a else a}  ->  {b.split('char_')[-1] if 'char_' in b else b}")
    # ---- 2. rename map: key = external name for functions/globals, (file,id) for locals
    order = []; seen = set()
    def dfs(f):
        if f in seen or not project(f): return
        seen.add(f); order.append(f)
        for a,b in sorted(edges):
            if a == f: dfs(b)
    dfs("main"); [dfs(f) for f in sorted(defined)]
    order = [f for f in order if f not in KEEP]; random.Random(SEED).shuffle(order)   # no name/structure-derived order
    newname = {f:f"fn_{i}" for i,f in enumerate(order)}
    newname["main"] = "main"
    repl = defaultdict(list); loc_ctr = defaultdict(int)
    idmap = {}; gnames = []
    gl = sorted({d[2] for r in per.values() for d in r["decl"] if d[0]=="VarDecl" and d[6] is None})
    random.Random(SEED+1).shuffle(gl); gmap = {g:f"gv_{i}" for i,g in enumerate(gl)}
    lc = defaultdict(int)
    for p, r in per.items():
        for k,i,name,extra,off,ln,fn,_ in r["decl"]:
            if k == "FunctionDecl":
                if name in newname: repl[p].append((off,ln,newname[name]))
            elif k == "ParmVarDecl":
                nn = f"pm_{extra}"; idmap[(p,i)] = nn; repl[p].append((off,ln,nn))
            elif fn is None:                                   # file-scope variable (definition or extern)
                repl[p].append((off,ln,gmap[name]))
            else:
                lc[(p,fn)] += 1; nn = f"lv_{lc[(p,fn)]}"; idmap[(p,i)] = nn; repl[p].append((off,ln,nn))
        for k,i,name,off,ln,fn,_ in r["ref"]:
            if (p,i) in idmap: repl[p].append((off,ln,idmap[(p,i)]))
            elif k == "FunctionDecl" and name in newname: repl[p].append((off,ln,newname[name]))
            elif k == "VarDecl" and name in gmap: repl[p].append((off,ln,gmap[name]))
    outdir = Path(sys.argv[0]).parent / "renamed"; outdir.mkdir(exist_ok=True)
    for p in FILES:
        src = p.read_bytes(); 
        for off,ln,nn in sorted(set(repl[p]), reverse=True): src = src[:off]+nn.encode()+src[off+ln:]
        (outdir/p.name).write_bytes(src)
    # ---- 3. validate
    ok = True
    for p in FILES:
        q = outdir/p.name
        c = subprocess.run(["clang","-fsyntax-only","-w","-I",INC,str(q)],capture_output=True,text=True)
        same_lines = p.read_bytes().count(b"\n") == q.read_bytes().count(b"\n")
        print(f"  renamed {p.name.split('char_')[-1]:28s} compiles={c.returncode==0}  same_line_count={same_lines}")
        ok &= c.returncode==0 and same_lines
    # graph isomorphism under the mapping
    edges2 = set()
    for p in FILES:
        _, tu = analyse(outdir/p.name)
        def visit(n, f, fn):
            if n.get("kind")=="CallExpr" and newname.get(fn,fn) in set(newname.values()):
                c = n["inner"][0]
                while c.get("kind") in ("ImplicitCastExpr","ParenExpr"): c = c["inner"][0]
                edges2.add((fn, c["referencedDecl"]["name"] if c.get("kind")=="DeclRefExpr" and c["referencedDecl"]["kind"]=="FunctionDecl" else "<INDIRECT>"))
        walk(tu, str(outdir/p.name), {"file":None}, None, visit)
    mapped = {(newname.get(a,a), newname.get(b,b)) for a,b in edges}
    print("  call graph isomorphic under rename:", mapped == edges2, f"({len(edges)} edges)")
    print("  mapping:", {k.split('char_')[-1]:v for k,v in newname.items()})
main()
