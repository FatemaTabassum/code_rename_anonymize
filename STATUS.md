# STATUS (updated 2026-09-26)

**Project:** Juliet CWE-415/416 -> anonymized group-level prompts for the LLM study (`progress_report_week.tex`). Code: `prompt_pipeline/`. Folder renamed from `vulchecker-misc-main` to `code_rename_anonymize` on 25 Sep; code that is not the user's is in `others/` (read-only).

**Now:** Step 2 (gate) is written and tested (`src/step_2_gate.py`, 10/10 tests pass) but has NOT been run on the real data yet. Steps 1-2 and the tests were written by Claude; the user has not reviewed the step code yet (tests were explained on 25 Sep). The user's notes in the two test files are committed (26 Sep).

**Last result:** Step 1 grouping run on CWE415 + CWE416 -> `prompt_pipeline/outputs/step_1/`. Expected after excluding the 6 "husk" groups: CWE-415 1,924 groups (962/962), CWE-416 918 (459/459).

**Next:**
1. Run step 2 on `outputs/step_1/CWE415_groups` and `CWE416_groups` (through `track.py`; one-line command in `prompt_pipeline/README.md`). Juliet headers now live in `prompt_pipeline/juliet_support/` (26 Sep; see `paper_notes.md`).
2. Check that the 6 husk groups (only `main`) are reported/excluded; compare with `claude_reference/check_group.py`.
3. Then step 3: rename (start from `src/prototype_cg_rename.py`).


**Background:** `discussions/discussion_personal_mac_1.md` (long; §12 is the 21 Sep handoff).
