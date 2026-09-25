# prompt_pipeline

Implementation of the plan in `../discussions/discussion_personal_mac_1.md` (section 7):
turn Juliet CWE-415/416 test cases into anonymized, group-level prompt text for the LLM study.
No LLVM IR is used; only `clang` (AST, `-c`) and `nm`.

## Steps -> modules (to be built)

| Step | What | Module |
|---|---|---|
| 1 | Group pieces by the filename rule (sample = group + omit type) | `src/step_1_grouping.py` |
| 2 | Gate: completeness / consistency check | `src/step_2_gate.py` (Claude's reference: `../claude_reference/check_group.py`) |
| 3 | Rename functions and variables, one group-wide map | `src/rename.py` (from `src/prototype_cg_rename.py`) |
| 4 | Build prompt text (ordered parts, neutral separators) | `src/build_prompt.py` |
| 5 | Optional: Joern call-graph / data-flow facts on renamed code | `src/graph_facts.py` |
| 6 | Run LLM, metrics incl. paired discrimination | outside this folder for now |

## Layout

- `src/` code, `tests/` tests, `outputs/` generated prompts (not committed).
- `src/prototype_cg_rename.py` is the throwaway prototype (copied from the session scratchpad); known gaps are listed in the discussion file, section 4.

## How to run

Run from the repo root (`vulchecker-misc-main/`). Each command goes through `track.py`, so the exact
command, code version and result are recorded in `runs/runs.jsonl` (list with `python3 track.py --last 10`).
Data: `/Users/fatema/projects/renaming_folder/CWE415`, `CWE416`.

**Step 1: grouping** (done, 22 Sep)

```bash
uv run python track.py --note "step 1: group CWE415" -- \
  uv run python prompt_pipeline/src/step_1_grouping.py \
  /Users/fatema/projects/renaming_folder/CWE415/source_files \
  prompt_pipeline/outputs/step_1/CWE415_groups

uv run python track.py --note "step 1: group CWE416" -- \
  uv run python prompt_pipeline/src/step_1_grouping.py \
  /Users/fatema/projects/renaming_folder/CWE416/source_files \
  prompt_pipeline/outputs/step_1/CWE416_groups

# coverage check (every source file lands in exactly one group)
uv run python prompt_pipeline/src/step_1_grouping.py --check \
  /Users/fatema/projects/renaming_folder/CWE415/source_files
```

**Step 2: gate** (not run yet; `-I` points at the folder with `std_testcase.h`)

```bash
uv run python track.py --note "step 2: gate CWE415" -- \
  uv run python prompt_pipeline/src/step_2_gate.py \
  prompt_pipeline/outputs/step_1/CWE415_groups \
  -I /Users/fatema/projects/renaming_folder/juliet/CWE190/source_files
```
