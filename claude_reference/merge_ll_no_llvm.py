"""
Merge per-source-file LLVM IR (.ll) text files that belong to the same Juliet
test-case variant into one valid module, WITHOUT requiring llvm-link or opt.

Grouping rule (which files belong together) is identical to merge_ll.py:
files are grouped by stem + variant number parsed from the filename.

Linking technique: LLVM IR references everything by name (@foo), so combining
two modules is mostly text concatenation. The only things that collide across
files are module-scoped numeric IDs -- metadata nodes ("!7 = ...") and
attribute groups ("attributes #0 = {...}") -- so each file's IDs are
renumbered with a running offset before merging. Per-function values (%0,
%1, ...) and basic-block labels are already scoped to their own function and
never collide, so they are left untouched.

What this does NOT do: real inlining or IR-level dead-code elimination
(that needs an actual optimizer, i.e. `opt`). This script only performs
linking (producing one syntactically/semantically valid module out of many),
not optimization. As a substitute correctness check, the merged output is
optionally verified with `clang` itself, which embeds the LLVM verifier.
"""

import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

VAR_RE = re.compile(r"([0-8][0-9])[a-z]?")
NUMBERED_RE = re.compile(r'([!#])(\d+)\b')
FUNC_NAME_RE = re.compile(r'@([^\s(]+)\s*\(')
GLOBAL_NAME_RE = re.compile(r'^(@[^\s=]+)\s*=')
ATTR_DEF_RE = re.compile(r'^attributes #(\d+) = \{.*\}$')
NUM_META_RE = re.compile(r'^!(\d+) = (.*)$')
NAMED_META_RE = re.compile(r'^(!llvm\.[\w.]+) = !\{(.*)\}$')


def group_by_variant(input_dir: Path) -> dict[str, list[Path]]:
    groups: dict[str, list[Path]] = defaultdict(list)
    for f in input_dir.iterdir():
        parts = f.name.split("_")
        if VAR_RE.fullmatch(parts[-2]):
            var_idx = -2
        elif VAR_RE.fullmatch(parts[-3]):
            var_idx = -3
        else:
            raise ValueError(f"Could not find variant number in {f.name}")

        base_var = VAR_RE.fullmatch(parts[var_idx]).group(1)
        omit_type = parts[-1].split(".")[0]
        if var_idx == -3 and base_var == "01":
            merged_name = f.name
        else:
            merged_name = "_".join(parts[:var_idx]) + f"_{base_var}_{omit_type}.ll"
        groups[merged_name].append(f)
    return groups


def renumber_file(text: str, meta_offset: int, attr_offset: int) -> tuple[str, int, int]:
    max_meta_seen = -1
    max_attr_seen = -1

    def repl(m: re.Match) -> str:
        nonlocal max_meta_seen, max_attr_seen
        sigil, num = m.group(1), int(m.group(2))
        if sigil == '!':
            max_meta_seen = max(max_meta_seen, num)
            return f'!{num + meta_offset}'
        max_attr_seen = max(max_attr_seen, num)
        return f'#{num + attr_offset}'

    new_text = NUMBERED_RE.sub(repl, text)
    next_meta_offset = meta_offset + max_meta_seen + 1
    next_attr_offset = attr_offset + max_attr_seen + 1
    return new_text, next_meta_offset, next_attr_offset


def parse_module(text: str) -> dict:
    lines = text.splitlines()
    header: dict[str, str] = {}
    globals_: dict[str, str] = {}
    declares: dict[str, str] = {}
    defines: dict[str, str] = {}
    attrs: dict[int, str] = {}
    num_meta: dict[int, str] = {}
    named_meta: dict[str, list[str]] = defaultdict(list)

    i, n = 0, len(lines)
    while i < n:
        line = lines[i]
        if line.startswith('; ModuleID'):
            header['modid'] = line
        elif line.startswith('source_filename'):
            header['srcfile'] = line
        elif line.startswith('target datalayout'):
            header['datalayout'] = line
        elif line.startswith('target triple'):
            header['triple'] = line
        elif line.startswith('define '):
            block = [line]
            i += 1
            while i < n and lines[i] != '}':
                block.append(lines[i])
                i += 1
            block.append('}')
            name = '@' + FUNC_NAME_RE.search(line).group(1)
            defines[name] = '\n'.join(block)
        elif line.startswith('declare '):
            name = '@' + FUNC_NAME_RE.search(line).group(1)
            declares[name] = line
        elif (m := ATTR_DEF_RE.match(line)):
            attrs[int(m.group(1))] = line
        elif (m := NUM_META_RE.match(line)):
            num_meta[int(m.group(1))] = line
        elif (m := NAMED_META_RE.match(line)):
            ids = [x.strip() for x in m.group(2).split(',') if x.strip()]
            named_meta[m.group(1)].extend(ids)
        elif (m := GLOBAL_NAME_RE.match(line)):
            globals_[m.group(1)] = line
        i += 1

    return {
        'header': header, 'globals': globals_, 'declares': declares,
        'defines': defines, 'attrs': attrs, 'num_meta': num_meta,
        'named_meta': named_meta,
    }


def merge_group(files: list[Path]) -> str:
    meta_offset = attr_offset = 0
    header: dict[str, str] = {}
    all_globals: dict[str, str] = {}
    all_declares: dict[str, str] = {}
    all_defines: dict[str, str] = {}
    all_attrs: dict[int, str] = {}
    all_num_meta: dict[int, str] = {}
    named_first: dict[str, list[str]] = {}
    named_union: dict[str, list[str]] = defaultdict(list)

    for f in sorted(files):
        text, meta_offset, attr_offset = renumber_file(f.read_text(), meta_offset, attr_offset)
        mod = parse_module(text)

        if not header:
            header = mod['header']

        for name, line in mod['globals'].items():
            existing = all_globals.get(name)
            if existing and 'external' not in existing and 'external' not in line:
                raise ValueError(f"Conflicting global definitions for {name}")
            if existing is None or 'external' in existing:
                all_globals[name] = line

        for name, block in mod['defines'].items():
            if name in all_defines:
                raise ValueError(f"Duplicate function definition for {name} across {files}")
            all_defines[name] = block

        for name, line in mod['declares'].items():
            all_declares.setdefault(name, line)

        all_attrs.update(mod['attrs'])
        all_num_meta.update(mod['num_meta'])

        for key, ids in mod['named_meta'].items():
            if key == '!llvm.module.flags':
                named_first.setdefault(key, ids)
            else:
                named_union[key].extend(ids)

    # A declare is redundant (and invalid alongside a define of the same
    # name) once some file in the group actually defines that function.
    for name in list(all_declares):
        if name in all_defines:
            del all_declares[name]

    out = [
        header.get('modid', "; ModuleID = 'merged'"),
        header.get('srcfile', 'source_filename = "merged"'),
    ]
    if 'datalayout' in header:
        out.append(header['datalayout'])
    if 'triple' in header:
        out.append(header['triple'])
    out.append('')

    out.extend(all_globals.values())
    out.append('')
    out.extend(all_declares.values())
    out.append('')
    for block in all_defines.values():
        out.append(block)
        out.append('')
    for attr_id in sorted(all_attrs):
        out.append(all_attrs[attr_id])
    out.append('')
    for key, ids in {**named_first, **named_union}.items():
        out.append(f'{key} = !{{{", ".join(ids)}}}')
    out.append('')
    for meta_id in sorted(all_num_meta):
        out.append(all_num_meta[meta_id])

    text = '\n'.join(out) + '\n'
    # Same intent as the sed hack in merge_ll.py: without opt around to
    # actually inline these functions, the optnone/noinline flags are just
    # inert leftovers, so strip them for a cleaner file.
    text = re.sub(r'\bnoinline\b', '', text)
    text = re.sub(r'\boptnone\b', '', text)
    return text


def verify_with_clang(ll_path: Path) -> tuple[bool, str]:
    result = subprocess.run(
        ["clang", "-S", "-emit-llvm", str(ll_path), "-o", "/dev/null"],
        capture_output=True, text=True,
    )
    return result.returncode == 0, result.stderr


def main(input_dir: Path, output_dir: Path, verify: bool = True) -> None:
    for merged_name, files in group_by_variant(input_dir).items():
        merged_text = merge_group(files)
        out_path = output_dir / merged_name
        out_path.write_text(merged_text)

        if verify:
            ok, stderr = verify_with_clang(out_path)
            status = "OK" if ok else "INVALID"
            print(f"[{status}] {merged_name}  ({len(files)} file(s) merged)")
            if not ok:
                print(stderr)
        else:
            print(f"[merged] {merged_name}  ({len(files)} file(s) merged)")


if __name__ == "__main__":
    if len(sys.argv) != 3 or not Path(sys.argv[1]).is_dir() or not Path(sys.argv[2]).is_dir():
        print(f"Usage: python3 {sys.argv[0]} <input-dir> <output-dir>")
        sys.exit(1)
    main(Path(sys.argv[1]), Path(sys.argv[2]))
