"""Step 1: group Juliet files into test-case groups (one group = one test case + one omit type)."""
import os
import re
import shutil
import sys
from pathlib import Path

# stem      : everything before the variant number, e.g. CWE415_Double_Free__malloc_free_char
# variant   : two digits, e.g. 53
# suffix    : optional piece letter (a, b, ...), grouped with its siblings; or a
#             named C++ role (_bad, _goodB2G, ...), which joins the group only
#             if a lettered piece is also present (see group_files)
# omit_type : omitbad (safe sample) or omitgood (vulnerable sample)
NAME_PATTERN = re.compile(
    r"^(?P<stem>.+)_(?P<variant>\d{2})(?P<suffix>[a-z]|_[A-Za-z0-9]+)?"
    r"_(?P<omit_type>omitbad|omitgood)\.(?:c|cpp)$"
)


def parse_name(filename: str) -> tuple[str, str, str] | None:
    """Return (stem, variant, omit_type), or None if the name does not match (e.g. headers)."""
    match = NAME_PATTERN.match(filename)
    if match is None:
        return None
    return match["stem"], match["variant"], match["omit_type"]


def group_files(filenames: list[str]) -> dict[tuple[str, str, str], list[str]]:
    """Map (stem, variant, omit_type) -> sorted list of file names in that group.

    A named piece (_bad, _good1, ...) joins its (stem, variant) group only
    when that group also has a lettered piece (a, b, ...) to attach to, e.g.
    CWE415 variant 81's `81a` driver plus its `81_bad` sink. Otherwise the
    named piece is a self-contained test case with its own main() (e.g.
    no_copy_const_01_bad vs. no_copy_const_01_good1) and must become its own
    group, keyed by stem+piece, or two mains would land in one sample.
    """
    names = sorted(filenames)
    matches = [(name, NAME_PATTERN.match(name)) for name in names]
    has_letter_piece = {
        (m["stem"], m["variant"])
        for _, m in matches
        if m is not None and m["suffix"] and len(m["suffix"]) == 1
    }

    groups: dict[tuple[str, str, str], list[str]] = {}
    for name, m in matches:
        if m is None:
            continue
        piece = m["suffix"] or ""
        standalone = piece.startswith("_") and (m["stem"], m["variant"]) not in has_letter_piece
        stem = m["stem"] + piece if standalone else m["stem"]
        key = (stem, m["variant"], m["omit_type"])
        groups.setdefault(key, []).append(name)
    return groups


def write_groups(source_dir: Path, out_dir: Path) -> int:
    """Copy every group into out_dir/<omit_type>/<stem>_<variant>/. Returns the number of groups."""
    groups = group_files(os.listdir(source_dir))
    for (stem, variant, omit_type), names in groups.items():
        group_dir = out_dir / omit_type / f"{stem}_{variant}"
        group_dir.mkdir(parents=True, exist_ok=True)
        header = source_dir / f"{stem}_{variant}.h"  # shared class header (C++ 81-84), if any
        for name in names + ([header.name] if header.exists() else []):
            shutil.copy2(source_dir / name, group_dir / name)
    return len(groups)


STEM = "CWE415_Double_Free__malloc_free_char"


def check_parse_name() -> None:
    """Check 1: parse_name splits names into (stem, variant, omit_type); headers give None."""
    print("--- check 1: parse_name")
    for name in [
        f"{STEM}_53a_omitgood.c",
        f"{STEM}_01_omitbad.c",
        f"{STEM}_81_goodB2G_omitbad.cpp",
        f"{STEM}_81.h",
    ]:
        print(f"{name} -> {parse_name(name)}")


def check_group_files() -> None:
    """Check 1b: pieces of one test case share a group; omit types stay apart."""
    print("--- check 1b: group_files on small examples")
    print(group_files([f"{STEM}_53a_omitgood.c", f"{STEM}_53b_omitgood.c", f"{STEM}_81.h", f"{STEM}_81_goodB2G_omitbad.cpp"]))
    print(group_files([f"{STEM}_53a_omitgood.c", f"{STEM}_53b_omitgood.c", f"{STEM}_53b_omitbad.c"]))


def check_coverage(source_dir: Path) -> None:
    """Check 2: every non-header file must land in exactly one group."""
    print("--- check 2: coverage on the real folder")
    files = os.listdir(source_dir)
    groups = group_files(files)

    # flatten {key: [file, ...]} into one list of every file found in a group
    in_groups = [name for names in groups.values() for name in names]
    non_headers = [f for f in files if not f.endswith(".h")]

    print(f"non-header files: {len(non_headers)}, files found in groups: {len(in_groups)}")
    print(f"files never grouped: {len(set(non_headers) - set(in_groups))}")
    print(f"files in more than one group: {len(in_groups) - len(set(in_groups))}")


if __name__ == "__main__":
    if sys.argv[1] == "--check":
        check_parse_name()
        check_group_files()
        check_coverage(Path(sys.argv[2]))
    else:
        source, out = Path(sys.argv[1]), Path(sys.argv[2])
        print(f"{write_groups(source, out)} groups written to {out}")

