"""
Merge per-source-file Juliet .c/.cpp files that belong to the same test-case
variant into a single translation unit, so that a single `clang -emit-llvm`
run (via create_ll.py) produces one already-linked .ll per variant directly.
This replaces merge_ll.py's job (which needed llvm-link + opt) by doing the
merge one step earlier in the pipeline, at the C source level, where "linking"
is just text concatenation.

Grouping rule (which files belong together) is identical to merge_ll.py:
group by stem + variant number + omit-type (omitbad/omitgood) parsed from
the filename, e.g. "..._64a_omitbad.c" and "..._64b_omitbad.c" both belong
to variant "64_omitbad".

Each merged file's original pieces are separated with `#line` directives
so that debug info (and therefore juliet-labeling's file+line-number JSON
labels) still points at the *original* per-piece filename and line numbers,
even though clang only ever sees the one merged file on disk. This was
verified empirically: clang honors #line for both !DISubprogram's file and
every !DILocation inside the function body.

What this does NOT do: real inlining or dead-code elimination (that needs
`opt`). It only produces one syntactically/semantically connected module,
same as merge_ll.py's llvm-link step did -- clang naturally resolves the
cross-file calls itself since it's compiling one translation unit.
"""

import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

VAR_RE = re.compile(r"([0-8][0-9])[a-z]?")


def group_by_variant(input_dir: Path) -> dict[str, list[Path]]:
    groups: dict[str, list[Path]] = defaultdict(list)
    for f in input_dir.iterdir():
        if f.suffix not in (".c", ".cpp"):
            continue
        parts = f.name.split("_")
        if VAR_RE.fullmatch(parts[-2]):
            var_idx = -2
        elif VAR_RE.fullmatch(parts[-3]):
            var_idx = -3
        else:
            raise ValueError(f"Could not find variant number in {f.name}")

        base_var = VAR_RE.fullmatch(parts[var_idx]).group(1)
        omit_type = parts[-1].split(".")[0]
        suffix = f.suffix
        if var_idx == -3 and base_var == "01":
            merged_name = f.name
        else:
            merged_name = "_".join(parts[:var_idx]) + f"_{base_var}_{omit_type}{suffix}"
        groups[merged_name].append(f)
    return groups


def merge_group(files: list[Path]) -> str:
    chunks = []
    for f in sorted(files):
        chunks.append(f'#line 1 "{f.name}"')
        chunks.append(f.read_text())
    return "\n".join(chunks) + "\n"


def verify_with_clang(src_path: Path) -> tuple[bool, str]:
    result = subprocess.run(
        ["clang", "-fsyntax-only", str(src_path)],
        capture_output=True, text=True,
    )
    return result.returncode == 0, result.stderr


def main(input_dir: Path, output_dir: Path, verify: bool = True) -> None:
    for merged_name, files in group_by_variant(input_dir).items():
        out_path = output_dir / merged_name
        if len(files) == 1:
            shutil.copy(files[0], out_path)
            action = "copied"
        else:
            out_path.write_text(merge_group(files))
            action = f"merged {len(files)} files"

        if verify:
            ok, stderr = verify_with_clang(out_path)
            status = "OK" if ok else "FAIL"
            print(f"[{status}] {merged_name}  ({action})")
            if not ok:
                print(stderr)
        else:
            print(f"[{action}] {merged_name}")


if __name__ == "__main__":
    if len(sys.argv) != 3 or not Path(sys.argv[1]).is_dir() or not Path(sys.argv[2]).is_dir():
        print(f"Usage: python3 {sys.argv[0]} <input-dir> <output-dir>")
        sys.exit(1)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
