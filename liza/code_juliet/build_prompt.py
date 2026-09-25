#!/usr/bin/env python3
"""Assemble one group's renamed files into the text shown to the model.

One sample = one group. The pieces are concatenated in reading order (the
driver first, then the sinks) behind neutral separators, because the original
file names carry the answer: they end in _omitbad / _omitgood, and in the
C++ class variants they are literally called ..._81_bad.cpp.

The text does not need to compile -- the model reads it -- so the merge is a
readability and token-count exercise, not a build step. Repeated #include
lines and the class header, which every piece of variants 81-84 includes, are
emitted once.
"""

import argparse
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from juliet.groups import collect_groups

INCLUDE_RE = re.compile(rb"^\s*#\s*include\s+[<\"][^>\"]+[>\"]", re.M)


def strip_repeated_includes(text, seen):
    """Drop #include lines already emitted by an earlier piece."""
    out = []
    for line in text.splitlines(keepends=True):
        m = INCLUDE_RE.match(line)
        if m:
            key = m.group(0).strip()
            if key in seen:
                continue
            seen.add(key)
        out.append(line)
    return b"".join(out)


def build(group, src_dir, dedupe=True):
    """Return the prompt text for one group."""
    files = [src_dir / p.name for p in group.files]
    files = [f for f in files if f.exists()]
    parts, seen = [], set()

    for i, path in enumerate(files, 1):
        text = path.read_bytes()
        if dedupe:
            text = strip_repeated_includes(text, seen)
        if not text.strip():
            continue
        header = "/* part {} of {} */\n".format(i, len(files)).encode()
        parts.append(header + text.rstrip() + b"\n")

    return b"\n".join(parts).decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source_dir", help="original corpus (for the grouping)")
    ap.add_argument("--renamed", required=True,
                    help="output root of cg_rename.py; each group is a subdirectory")
    ap.add_argument("--header-dir", action="append", default=[])
    ap.add_argument("--group", help="build only this group")
    ap.add_argument("--out", help="write one .txt per group here")
    ap.add_argument("--no-dedupe", action="store_true")
    args = ap.parse_args()

    groups, _ = collect_groups(args.source_dir, args.header_dir)
    names = [args.group] if args.group else sorted(groups)
    renamed_root = Path(args.renamed)

    out_dir = Path(args.out) if args.out else None
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)

    written = 0
    for name in names:
        group = groups.get(name)
        if group is None:
            sys.exit("no such group: " + name)
        gdir = renamed_root / name
        if not gdir.is_dir():
            continue
        text = build(group, gdir, dedupe=not args.no_dedupe)
        if out_dir:
            (out_dir / (name + ".txt")).write_text(text)
            written += 1
        else:
            print(text)
    if out_dir:
        print("wrote {} prompts to {}".format(written, out_dir))


if __name__ == "__main__":
    sys.exit(main())
