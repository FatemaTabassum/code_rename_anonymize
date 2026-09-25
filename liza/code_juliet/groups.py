"""Group Juliet source files into test cases.

A Juliet test case is split across several files ("pieces"). The filename
encodes which test case a piece belongs to, which variant it is, and whether
the bad or the good function was omitted:

    <stem>_<NN><piece>_omit{bad,good}.{c,cpp}

<piece> is empty for single-file variants, a letter (a-e) for the flow
variants, or one of _bad / _goodG2B / _goodB2G / _good1 for the C++ class
variants.

Named pieces (_bad, _good1, ...) mean two different things depending on the
variant, so the piece suffix alone cannot decide the grouping:

  * In variants 81-84 they are sinks belonging to the <NN>a driver, which
    holds main. They join that group.
  * In the single-file class variants (no_copy_const_01, operator_equals_01)
    each named piece is a self-contained test case with its own main. Under
    the opposite omit type it degrades to a husk -- an empty namespace and an
    empty main -- but that husk still defines main, so merging them would put
    two mains in one sample.

The rule: named pieces join the group only when the (stem, variant) also has
a letter piece to attach to. Otherwise each named piece is its own group.

One sample = one group = one stem + one variant number + one omit type.
The 81-84 class header (<stem>_<NN>.h) carries no omit type and belongs to
both of its group's omit types.

Verified against a symbol-link check (scripts/juliet/check_group.py): the
filename rule never splits a connected test case.
"""

import re
from collections import defaultdict
from pathlib import Path

SOURCE_SUFFIXES = {".c", ".cpp"}

# <stem>_<NN><piece>_omit<type>.<ext>
PIECE_RE = re.compile(
    r"^(?P<stem>.+?)_(?P<variant>[0-9]{2})(?P<piece>[a-z]|_bad|_goodG2B|_goodB2G|_good1)?"
    r"_omit(?P<omit>bad|good)\.(?P<ext>c|cpp)$"
)

# <stem>_<NN>.h  -- the class header shared by variants 81-84
HEADER_RE = re.compile(r"^(?P<stem>.+?)_(?P<variant>[0-9]{2})\.h$")


class Group:
    """One sample: every piece of one test case under one omit type."""

    def __init__(self, stem, variant, omit):
        self.stem = stem
        self.variant = variant
        self.omit = omit
        self.sources = []   # Path, sorted by piece order
        self.headers = []   # Path

    @property
    def name(self):
        return "{}_{}_omit{}".format(self.stem, self.variant, self.omit)

    @property
    def label(self):
        # _omitgood keeps only the bad function; _omitbad keeps only the good one.
        return "vul" if self.omit == "good" else "non_vul"

    @property
    def files(self):
        return self.headers + self.sources

    def __repr__(self):
        return "<Group {} {} pieces>".format(self.name, len(self.sources))


def piece_sort_key(path):
    """Order pieces the way the test case reads: a, b, c... then the class files."""
    m = PIECE_RE.match(path.name)
    piece = (m.group("piece") or "") if m else ""
    if len(piece) == 1:
        return (0, piece)
    return (1, piece)


def collect_groups(source_dir, header_dirs=()):
    """Return {group_name: Group} for every test case under source_dir."""
    source_dir = Path(source_dir)
    groups = {}
    headers = defaultdict(list)
    unmatched = []
    parsed = []
    has_letter_piece = set()

    header_paths = [p for d in header_dirs for p in Path(d).iterdir()]
    header_paths += [p for p in source_dir.iterdir() if p.suffix == ".h"]
    for path in header_paths:
        m = HEADER_RE.match(path.name)
        if m:
            headers[(m.group("stem"), m.group("variant"))].append(path)

    for path in sorted(source_dir.iterdir()):
        if path.suffix not in SOURCE_SUFFIXES:
            continue
        m = PIECE_RE.match(path.name)
        if not m:
            unmatched.append(path)
            continue
        parsed.append((path, m))
        if m.group("piece") and len(m.group("piece")) == 1:
            has_letter_piece.add((m.group("stem"), m.group("variant")))

    for path, m in parsed:
        stem, variant = m.group("stem"), m.group("variant")
        piece = m.group("piece") or ""
        standalone = piece.startswith("_") and (stem, variant) not in has_letter_piece
        key = (stem + piece if standalone else stem, variant, m.group("omit"))
        group = groups.get(key)
        if group is None:
            group = groups[key] = Group(*key)
        group.sources.append(path)

    for (stem, variant, _omit), group in groups.items():
        stem = stem.split("_bad")[0].split("_good")[0]
        group.sources.sort(key=piece_sort_key)
        seen = set()
        for path in headers.get((stem, variant), []):
            if path.name not in seen:
                seen.add(path.name)
                group.headers.append(path)

    return {g.name: g for g in groups.values()}, unmatched
