# Discussion 1 (personal Mac): grouping, call graph, renaming, gate, plan

Date: 2026-09-21
Scope: Juliet CWE-415 (double free) and CWE-416 (use after free)
Goal (confirmed): the **LLM prompt study** (`liza/progress_report_week.tex`), not the VulChecker replication.
Consequence: no LLVM IR is needed. `clang` is still fine to use (its AST, and `clang -c` + `nm`).

---

## 1. Starting point

Two scripts in `scripts/` merge Juliet pieces of one test case:

| Script | Level | How it merges |
|---|---|---|
| `merge_c.py` | source | Concatenates pieces, inserts `#line 1 "<orig file>"` between them |
| `merge_ll_no_llvm.py` | LLVM IR text | Concatenates `.ll` text, renumbers `!N` metadata and `#N` attributes |
| `merge_ll.py` (original) | LLVM IR | `llvm-link` then `opt --inline` then `internalize` + `globaldce` |

Grouping rule, shared by all three: file name -> stem + variant number (`[0-8][0-9]` plus optional letter) + `omitbad`/`omitgood`.
Example: `..._53a/b/c/d_omitgood.c` -> group `..._53_omitgood.c`.
`omitbad` (good-only code) and `omitgood` (bad-only code) are always separate samples.

---

## 2. Findings

### 2.1 `merge_c.py` compile check (all files, `clang -fsyntax-only`)

| | Output files | Compile OK | Fail |
|---|---|---|---|
| CWE416 | 920 | 920 | 0 |
| CWE415 | 1,928 | 1,728 | 200 |

All 200 failures are `redefinition of ...`, two causes:

1. **C++ variants 81-84 (160 files):** every piece includes a class header (`..._81.h`, ...) with no include guard, so the class is defined once per piece. De-duplicating the repeated `#include "<local>.h"` fixed 81 (both omit types, 0 errors). 82-84 not re-run.
2. **C variant 67 (40 files):** `67a` and `67b` both define the same `typedef struct`. Fix not tested.

Both only matter if the merged text must compile. For the LLM study it does not (see section 6).

### 2.2 The LLVM pipeline (`merge_ll.py`) is sound but incomplete

- Each stage preserves semantics (`llvm-link`, inlining, internalize + `globaldce` with `main` as the only root).
- Incomplete: in the existing `CWE415/ll_files/optimized` output, only 1,576 of 1,928 files (82%) were flattened to just `main`. Not flattened: variants 44, 65 (function pointers), 72, 73 (half), 74 (C++ containers), 81-84 (virtual calls, ctors/dtors), 68 (12 of 40, cause not found). Reason for 44/65: no `mem2reg`/`instcombine` runs, so indirect calls are never folded to direct calls.
- Other weaknesses: `sed` strips `noinline`/`optnone` without a word boundary; `subprocess.run` never checks return codes; grouping is by filename with no closure check.
- I could not rerun it (`opt` and `llvm-link` are not installed here); this is from inspecting existing output.

### 2.3 Why the original project uses LLVM IR (not needed for this study)

`process_all.py` runs a custom LLVM pass (`LLVM_HECTOR_415.so`) with `opt` over each `.ll` plus a label JSON to produce `labeled_graphs/*.json`. Labels are source file + line (`juliet-labeling/cwe415.py`: `first_free`, `second_free`); debug info (`-g`) maps them onto IR instructions. CFGAVE separately extracts per-function block features from compiled binaries (BinaryNinja). The pass source is not in this repo, so its exact graph contents are unverified.

### 2.4 Grouping verified two ways

Independent check: compile every file, read symbols with `nm` ("I have" = defined, "I need" = undefined), join files whose needs match another's haves.

| | Filename groups | Identical to symbol groups |
|---|---|---|
| CWE416 | 920 | 920 (100%) |
| CWE415 | 1,928 | 1,768 (92%) |

- The 160 CWE415 differences are all C++ 81-84: after the `omit` preprocessing some pieces are empty (define nothing), so no symbol link can reach them. The filename rule keeps them in the group; harmless. 244 empty pieces in CWE415, 2 in CWE416.
- **No symbol group spans two filename groups (0):** the filename rule never splits a connected test case.
- My first run wrongly flagged 12 files (variant 68) as missing definitions. That was my bug: uninitialized globals appear in `nm` as common symbols (`C`). After the fix: 0 unresolved.
- Only CWE415 and CWE416 were checked. Other CWEs are untested.

Decision: keep the filename rule for grouping; use the symbol check as a gate.

---

## 3. Renaming: what the report requires

From `liza/progress_report_week.tex`:

- The current anonymization (Joern + libclang, name regex `.*CWE.*`) leaves 2,288 of 3,368 CWE415 files (68%) with a label-bearing identifier (Gap 1: C++ namespaced `bad()`/`badSink`) and never sees class/struct names (Gap 2: no `cpg.typeDecl` query).
- Planned fix: rename by **where a symbol is declared** (declared in the corpus), not by its name.
- GPT-4o baseline: 53.8% accuracy on CWE-415; paired discrimination 11.4% (187/1,644), below 25% chance.

**Scope decision (user): rename only functions and variables** (functions, globals, locals, parameters). Not types, namespaces, fields, macros, comments or string literals. Consequence: identifier leaks remain by design (comments such as `BadSource:`, strings like `"Calling bad()..."`, macros `OMITBAD`, class/namespace names in C++ 81-84). Any leak count must state this.

Note: the FSU copy of the report (`~/FSU/Fall_2026_reports/progress_report_week.tex`) differs from the `liza/` copy; only the `liza/` copy was read.

---

## 4. The prototype (`cg_rename.py`, scratchpad, ~120 lines)

Steps:

1. Ask clang for a JSON AST of each file (`clang -fsyntax-only -Xclang -ast-dump=json`). Every name is already resolved to its declaration.
2. Collect declarations and references whose location is inside the group's own files (declaration-site rule; ignores `malloc`, `free`, `printLine`).
3. Build the call graph from `CallExpr` nodes.
4. Choose new names with one group-wide map: functions `fn_N`, globals `gv_N`, locals `lv_N`, parameters `pm_<position>`. Numbering uses a **seeded shuffle**, not call-graph order or alphabetical order, so the number does not reveal which function is bad.
5. Rewrite files by exact byte offset, back to front. No regex.
6. Validate: each renamed file compiles; same line count; call graph recomputed on renamed code is isomorphic to the original under the mapping.

Results: groups CWE415 53 (a-d), 22 (a-b, shared global), 65 (a-b, function pointer) and CWE416 63 (a-b, pointer-to-pointer) all passed the three validations.

Bugs found and fixed while building it:
- File tracking in clang's JSON (`file` appears only when it changes; must follow clang's own key order for `spellingLoc`/`expansionLoc`).
- Header-defined inline functions leaked into the call graph (now only functions defined in the group).
- Prototype and definition got different parameter names (now keyed by position).
- Global variables were not renamed (now are: `gv_N`, `extern` and definition match across files).

Known gaps (not done):
- Indirect calls: `65_bad -> <INDIRECT>` is not resolved to `65b_badSink`. Needs address-taken tracking + points-to.
- C++ (81-84, 72-74): methods, constructors, virtual dispatch untested.
- Compiler builtins (e.g. `__builtin_object_size` from `memset`) appear as call edges and should be filtered.
- No data-flow edges yet.
- Only four groups tested.

---

## 5. Tooling decision: clang vs Joern

| | Clang AST | Joern CPG |
|---|---|---|
| Name resolution | Exact (it is the compiler) | Approximate (fuzzy parser) |
| Rewrite positions | Exact offsets | Not reliable enough to rewrite from |
| Needs to compile | Yes | No |
| Data-flow graph | Must be built | Built in |

Decision: **clang renames; Joern (optionally) supplies call-graph and data-flow facts for the prompt.** Joern was not run or tested here.

Rules for the Joern facts:
1. Run Joern on the **renamed** code, so facts say `fn_2`, not `badSink`.
2. Treat "with graph facts" as a **separate experimental condition**, not part of the baseline: the facts (e.g. "buffer freed in fn_2 reaches free in fn_3") nearly give the answer, which changes the question the study asks.
3. Joern data flow is not path-sensitive and may be weak on pointer-to-pointer (63), function pointers (65) and C++ virtual calls (81-84). Pilot on about 20 groups spanning variant types before scaling, and cross-check Joern's call graph against the clang call graph.

---

## 6. Gate script

`scripts/check_group.py` (new file). A gate answers PASS/FAIL for one group before it goes downstream (a checkpoint, not a transform).

Per group, each piece is compiled (`clang -c`) and read with `nm`.

| Check | Meaning |
|---|---|
| COMPILES | Every piece compiles on its own |
| CLOSED | Every needed project symbol (name contains `CWE`) is defined by some piece in the group |
| NO_DUP_DEF | No project symbol is strongly defined by two pieces (compiler-generated C++ vtable/typeinfo symbols are ignored) |
| CONNECTED | All pieces that define project symbols form one chain of have/need links |
| ONE_MAIN | At most one piece defines `main` |
| (report only) EMPTY, NO_MAIN | Pieces defining nothing; group without `main` |

Usage: `python3 check_group.py <source-dir> [-I include_dir ...] [--cache obj_dir] [--group NAME]`

Test results:
- Broken variants of group 53 all FAIL correctly: `53c` missing (CLOSED + CONNECTED), duplicated `53d` (NO_DUP_DEF), unrelated extra file (CONNECTED).
- Full data: CWE416 920/920 pass; CWE415 1,928/1,928 pass after ignoring generated C++ symbols. (First run reported 80 CWE415 failures; all were false alarms on `_ZTI`/`_ZTS`/vtable symbols, fixed.)
- A pass means the group is complete and consistent; it says nothing about renaming or later stages.

Uses `clang` and `nm` only (no LLVM IR tools). `clang -c` still runs LLVM's code generator inside clang.

---

## 6b. What the LLM study no longer needs

`llvm-link`, `opt`, `.ll` files, `merge_ll.py`, `merge_ll_no_llvm.py`, `create_ll.py`, `process_all.py`, CFGAVE, and the line labels from `juliet-labeling`. The sample label is just the omit type (`omitgood` = vulnerable, `omitbad` = safe).

Because the LLM reads text, the merged text does **not** need to compile, so the 200 merge failures in 2.1 do not block the study, and the `#line` trick is unnecessary. What remains is readability and token use: remove repeated `#include` lines and duplicate class/struct definitions.

---

## 7. Plan (pipeline for the LLM prompt study)

1. **Group** by the filename rule. Sample = one group + one omit type. Header files are not separate samples; include each class header (81-84) once in its group's text.
2. **Gate** every group with `check_group.py`.
3. **Rename** functions and variables with the clang prototype, using one group-wide map (same new names across all files of a group).
4. **Build the prompt text:** files in order (`a, b, c, d`) with neutral separators such as "part 2 of 4". Do not use original file names (they contain `omitbad`/`omitgood`).
5. **Optional second experiment:** add Joern call-graph/data-flow facts computed on the renamed code.
6. **Run the LLM** and compute metrics, including paired discrimination over the `omitbad`/`omitgood` pairs.

Order relative to the weekly plan: finish the anonymization fix and its leak audit first; only then adopt group-level samples.

---

## 8. Consequences to flag to the professor (methods)

- Aggressive renaming diverges from how the original benchmark authors preprocessed Juliet (already an open question in the report).
- **Changing the sample unit from file to group** is a second methods change: 3,288 CWE-415 files become 1,928 group samples (about 964 pairs), so the paired-discrimination denominator (currently 1,644) changes. In multi-file variants a single-file prompt shows only part of the bug (in 53, `53a` frees the buffer but the second free is in `53d`); this may contribute to the false-positive pattern, but that is a hypothesis, not tested.
- Adding graph facts changes what is being measured (section 5, rule 2).

---

## 9. Open items

- [ ] Build a script that runs steps 1-4 on one group so an example prompt can be inspected (awaiting user go-ahead).
- [ ] Prototype: resolve indirect calls (65), handle C++ 72-74 and 81-84, filter builtins, add data-flow edges, run beyond 4 groups.
- [ ] Add a leak audit (identifier-only, per the scope decision) as an acceptance check after renaming.
- [ ] Add alpha-equivalence check (token streams equal after mapping identifiers to first-occurrence ordinals) and optionally an ASan behavior comparison.
- [ ] Install/run Joern; pilot on about 20 groups; compare against the clang call graph.
- [ ] Decide whether other CWEs need the same grouping check.

## 10. Files

| Path | Status |
|---|---|
| `scripts/merge_c.py`, `merge_ll.py`, `merge_ll_no_llvm.py`, `create_ll.py`, `process_all.py` | existing, unchanged |
| `scripts/check_group.py` | new (gate script) |
| `discussions/discussion_personal_mac_1.md` | this file |
| Prototype `cg_rename.py`, grouping comparison `symgroups.py`, test groups | in the session scratchpad only (temporary, not in the project) |
| Data | `/Users/fatema/projects/renaming_folder/CWE415`, `CWE416` (`source_files`, `ll_files`, ...) |

---

## 11. Update (2026-09-21, later): `code_juliet` checked, `slicing` reviewed and dropped

Layout note: `code_juliet/`, `discussions/` and `prompt_pipeline/` now live under `liza/`.

**Step 1 (grouping) verified.** `code_juliet/groups.py` gives 1,928 groups (CWE-415) and 920 (CWE-416), 0 unmatched files, identical partitions to `scripts/merge_c.py`'s grouping. Labels balanced: 964 vulnerable / 964 safe (CWE-415), 460 / 460 (CWE-416). Spot checks: `53_omitgood` = 53a-53d in order; `81_omitbad` = 81a, 81_bad, 81_goodB2G, 81_goodG2B plus `81.h`. Only `groups.py` was tested; the rest of `code_juliet` (gate, renamer, prompt builder, leak audit) is unverified, and its README paths (`storage/...`, `scripts/juliet/...`) do not exist on this machine.

**`slicing/` was reviewed, then deleted by the user.** Run on the CWE-415/416 `source_files` (the JSON it expects was not available):
- Grouped by stem without the omit type: 962 / 459 clusters, every one mixing `omitbad` and `omitgood` files.
- Looked up functions by exact name (`bad`, `badSink`, `goodG2B`, `goodB2G`): only 252 of 962 (CWE-415) and 28 of 459 (CWE-416) clusters produced any sample. C files carry the CWE prefix; C++ multi-hop sinks are `badSink_b`, `badSink_c`, ...
- Needs the original label-bearing names, so it cannot run after renaming (the plan renames first).
- `sample_builder.py` emitted identical text with both labels.

**Idea kept for step 5 (Joern facts):** a compact, capped evidence block in the prompt (call trace, source-to-sink paths, resource lifecycle summary). Requirements: compute it on the renamed code, use real computed paths (not the source x sink cross product that `slicing` produced), and keep it a separate experimental condition.

---

## 12. Handoff for a new session (state as of 2026-09-21)

**Read sections 1-11 above first; this section is the current state and the next step.**

### Goal and decisions (settled with the user)
- Goal: the **LLM prompt study** (`liza/progress_report_week.tex`), not the VulChecker replication. No LLVM IR; `clang` (AST, `-c`) and `nm` are fine. Joern (optional, later) only for graph facts on the *renamed* code, as a separate experimental condition.
- Rename **functions and variables only** (not types, namespaces, fields, macros, comments, strings). Identifier leaks in the other channels remain by design.
- Sample = one group + one omit type (`omitgood` = vulnerable, `omitbad` = safe). Grouping = filename rule; the symbol-link gate is a check, not the grouping method.
- The user wants to **build it themselves, step by step**, with me guiding and reviewing; explanations in plain language.

### Step 1 (grouping) re-verified: `liza/code_juliet/groups.py`
Checked on CWE-415 (3,288 source files) and CWE-416 (1,040): every file in exactly one group, no unmatched files; piece file names match the group's omit type; every local `#include "...h"` resolves to an attached header (80 headers, CWE-415 only); both omit types of a header-carrying test case get the header; letter pieces sorted; no `non_vul` group defines or calls a bad function.

**Defect found: 6 "husk" groups contain no code except `main()`** (an empty namespace + `main`). They arise in the standalone `_bad` / `_good1` test cases (`no_assignment_op`, `no_copy_const` in CWE-415; `operator_equals` in CWE-416) where the omit step removes everything:
- `..._good1_01_omitgood` x3 are labeled `vul` but contain no bad code (mislabeled).
- `..._bad_01_omitbad` x3 are labeled `non_vul` but are empty (meaningless).

Corrected counts after excluding husks: CWE-415 **1,924 groups (962 vul / 962 safe)**, CWE-416 **918 groups (459 / 459)**. The 1,928 / 920 quoted earlier include the husks.

### Next step
1. **Step 2, gate.** Test `liza/code_juliet/check_group.py` (228 lines, untested) against the reference gate `scripts/check_group.py` on the real data; add exclusion of "no code besides `main`" groups (the gate reports these as `EMPTY`; `groups.py` has no compiler information to detect them).
2. Then step 3 (rename), step 4 (prompt text), leak audit, optional Joern facts.

### Files and status
| Path | Status |
|---|---|
| `liza/code_juliet/groups.py` | verified (above) |
| `liza/code_juliet/check_group.py`, `cg_rename.py`, `build_prompt.py`, `leak_audit.py` | **unverified**; origin unknown; README paths (`storage/...`, `scripts/juliet/...`) do not exist on this machine |
| `scripts/check_group.py` | my reference gate; tested: fails the 3 broken variants of group 53; passes all 1,928 + 920 groups (after ignoring generated C++ vtable/typeinfo symbols) |
| `liza/prompt_pipeline/src/prototype_cg_rename.py` | renaming prototype (functions, globals, locals, params; passed 4 groups); known gaps in section 4 |
| `liza/prompt_pipeline/src/step_1_grouping.py` | empty file created by the user (their own step 1, not started) |
| `liza/progress_report_week.tex` | the report; the FSU copy (`~/FSU/Fall_2026_reports/`) differs and was not read |
| Data | `/Users/fatema/projects/renaming_folder/CWE415`, `CWE416` (`source_files`, ...); `std_testcase.h` in `renaming_folder/juliet/CWE190/source_files` |
| `slicing/` | reviewed and deleted by the user (section 11) |

Copies of this file: `liza/discussions/` and `/Users/fatema/projects/merge_/discussions/` (kept identical by hand).
