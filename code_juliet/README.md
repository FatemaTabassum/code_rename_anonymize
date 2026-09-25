# Juliet group pipeline

Implements the plan in `discussions_folder/discussion_personal_mac_1.md` §7.
The sample unit is a **group** (one test case, one omit type), not a file.

| Step | Script | What it does |
|---|---|---|
| 1. Group | `groups.py` | Filename rule → 1,928 groups (CWE-415), 920 (CWE-416) |
| 2. Gate | `check_group.py` | PASS/FAIL per group before anything downstream |
| 3. Rename | `cg_rename.py` | Declaration-site renaming of functions and variables |
| 4. Prompt | `build_prompt.py` | Concatenate a group's pieces behind neutral separators |
| — Audit | `leak_audit.py` | Count surviving label tokens, split by scope category |

Everything uses `clang` and `nm` only. No LLVM IR tools, no Joern.

## Running it

`std_testcase.h` is not shipped in the CWE-415/416 trees; the copy in
`storage/CWE190/header_files` is the same file and is used as the include path.

```bash
CWE=CWE415
INC="-I storage/CWE190/header_files --header-dir storage/$CWE/header_files"

python3 scripts/juliet/check_group.py storage/$CWE/source_files $INC --jobs 12
python3 scripts/juliet/cg_rename.py   storage/$CWE/source_files $INC --out storage/$CWE/renamed --jobs 12
python3 scripts/juliet/leak_audit.py  storage/$CWE/renamed
python3 scripts/juliet/build_prompt.py storage/$CWE/source_files \
        --renamed storage/$CWE/renamed --header-dir storage/$CWE/header_files \
        --out storage/$CWE/prompts
```

## Scope, and what it means for the leak number

Per §3 of the discussion, renaming covers **functions and variables only**.
Types, namespaces, fields, macros, comments and string literals are left
alone. So `leak_audit.py` reports five columns and only the first is an
acceptance criterion:

- `identifier` — in scope. Any hit is a real miss.
- `type_or_ns`, `macro`, `comment`, `string` — out of scope by decision.

The weekly report (`Fall_report/progress_report_week.tex`) asks for the leak
rate to "drop to zero". That target is only meaningful for the `identifier`
column. Reaching zero overall additionally needs comment stripping and macro
removal, which is what `clean_setup_1` already does — so **the renamer should
run on `clean_setup_1` output, not on the raw corpus.**

## Findings worth keeping

Two things differ from what the discussion assumed, both verified here:

1. **`_01_bad` / `_01_good1` are separate test cases, not pieces.** In
   `no_copy_const_01`, `no_assignment_op_01` (CWE-415) and
   `operator_equals_01` (CWE-416), each file has its own `main`; under the
   opposite omit type it degrades to a husk that still defines `main`.
   Grouping them would put two `main`s in one sample. Splitting them is what
   makes the counts come out at 1,928 / 920.

2. **Variants 81-84 are linked only through the vtable.** The `81a` driver
   builds a subclass and calls `action()` through a base reference — virtual
   call, implicit constructor — so the sink piece is never referenced by
   name. Its single undefined project symbol is `_ZTV...`. Those symbols must
   be excluded from duplicate-definition checking but kept as connectivity
   evidence, or all 80 of those groups fail `CONNECTED`.

## Known gaps

- C++ methods, constructors and destructors are counted and reported but
  never renamed (variants 72-74, 81-84). `cg_rename.py` prints the count.
- Indirect calls show as `<INDIRECT>`; resolving variant 65 needs points-to
  analysis.
- No data-flow edges. Joern is not wired in yet; when it is, it runs on the
  *renamed* code and counts as a separate experimental condition.
