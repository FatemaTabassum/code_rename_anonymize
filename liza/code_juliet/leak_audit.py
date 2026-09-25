#!/usr/bin/env python3
"""Count label-bearing tokens that survive renaming, by category.

The renamer's scope is identifiers only (functions and variables). Comments,
string literals, macro names, types and namespaces are deliberately left
alone. A single "68% of files still leak" number cannot tell those apart, so
it cannot say whether the pipeline did its job or not.

This splits the count four ways:

    identifier   in scope -- any hit here is a real miss by the renamer
    type_or_ns   class, struct and namespace names (out of scope by decision)
    macro        OMITBAD / OMITGOOD and other preprocessor names (out of scope)
    comment      out of scope; removed by clean_setup_1, not by the renamer
    string       out of scope; "Calling bad()..." and friends

Only the first column is an acceptance criterion. The others are the price of
the scope decision and belong in the methods section, not in a bug report.
"""

import argparse
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

# The verdict is in these tokens: bad/good name the label directly, the rest
# are the Juliet template's own vocabulary for source and sink roles.
LABEL_RE = re.compile(r"(?i)(cwe\d+|\bbad\b|\bgood\b|bad[A-Z_]|good[A-Z_]|"
                      r"sink|source|flaw|omitbad|omitgood)")
IDENT_RE = re.compile(r"[A-Za-z_]\w*")
# Names introduced by the renamer itself, which obviously must not count.
RENAMED_RE = re.compile(r"^(fn|gv|lv|pm)_\d+$")

TYPE_KEYWORDS = ("class", "struct", "namespace", "union", "typedef", "enum")


def split_source(text):
    """Split C/C++ text into (code, comments, strings).

    A hand-rolled scanner rather than a regex: a `//` inside a string literal
    is not a comment, and a quote inside a comment does not open a string.
    Getting that backwards is what makes naive leak counts wrong.
    """
    code, comments, strings = [], [], []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            comments.append(text[i:j])
            code.append(" ")
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            comments.append(text[i:j])
            code.append(" ")
            i = j
        elif c in "\"'":
            quote, j = c, i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == quote:
                    j += 1
                    break
                j += 1
            strings.append(text[i:j])
            code.append(" ")
            i = j
        else:
            code.append(c)
            i += 1
    return "".join(code), "\n".join(comments), "\n".join(strings)


def type_names(code):
    """Identifiers introduced as a class/struct/namespace/enum name."""
    names = set()
    for kw in TYPE_KEYWORDS:
        for m in re.finditer(r"\b{}\s+([A-Za-z_]\w*)".format(kw), code):
            names.add(m.group(1))
    return names


def audit_text(text):
    """Return {category: Counter(token)} for one file."""
    code, comments, strings = split_source(text)
    types = type_names(code)
    out = defaultdict(Counter)

    for line in code.splitlines():
        stripped = line.lstrip()
        bucket_default = "macro" if stripped.startswith("#") else None
        for ident in IDENT_RE.findall(line):
            if RENAMED_RE.match(ident) or not LABEL_RE.search(ident):
                continue
            if bucket_default:
                out["macro"][ident] += 1
            else:
                out["type_or_ns" if ident in types else "identifier"][ident] += 1

    for label, blob in (("comment", comments), ("string", strings)):
        for m in LABEL_RE.finditer(blob):
            out[label][m.group(0)] += 1
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("root", help="directory of renamed groups, or of source files")
    ap.add_argument("--ext", default=".c,.cpp,.h,.txt")
    ap.add_argument("--top", type=int, default=12)
    args = ap.parse_args()

    exts = set(args.ext.split(","))
    files = [p for p in Path(args.root).rglob("*") if p.suffix in exts]
    if not files:
        sys.exit("no source files under " + args.root)

    totals = defaultdict(Counter)
    files_hit = Counter()

    for path in files:
        per_file = audit_text(path.read_text(errors="replace"))
        for cat, counter in per_file.items():
            if counter:
                files_hit[cat] += 1
                totals[cat] += counter

    print("{} files scanned under {}\n".format(len(files), args.root))
    print("{:<14} {:>8} {:>8}   {}".format("category", "files", "%", "top tokens"))
    print("-" * 78)
    for cat in ("identifier", "type_or_ns", "macro", "comment", "string"):
        top = ", ".join(t for t, _ in totals[cat].most_common(4))
        print("{:<14} {:>8} {:>7.1f}%   {}".format(
            cat, files_hit[cat], 100.0 * files_hit[cat] / len(files), top))

    print("\nACCEPTANCE (identifier column only): {}".format(
        "PASS -- no label-bearing identifier survives" if not files_hit["identifier"]
        else "FAIL -- {} files still carry one".format(files_hit["identifier"])))

    if totals["identifier"]:
        print("\nsurviving identifiers:")
        for tok, n in totals["identifier"].most_common(args.top):
            print("   {:<50s} {}".format(tok, n))


if __name__ == "__main__":
    sys.exit(main())
