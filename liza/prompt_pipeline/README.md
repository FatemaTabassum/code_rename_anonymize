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
