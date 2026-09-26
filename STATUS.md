# STATUS (updated 2026-09-26)

**Project:** Juliet CWE-415/416 -> anonymized group-level prompts for the LLM study (`progress_report_week.tex`). Code: `prompt_pipeline/`. Folder renamed from `vulchecker-misc-main` to `code_rename_anonymize` on 25 Sep; code that is not the user's is in `others/` (read-only).

**Now:** Step 2 (gate) ran on CWE-415. Still to run on CWE-416. Steps 1-2 and the tests were written by Claude; the user has not reviewed the step code yet. Repo is on GitHub (private): https://github.com/FatemaTabassum/code_rename_anonymize

**Last result:** Step 2 on CWE-415 (run 20260926-170402): 1,928 groups, all PASS. Expected 1,924 after dropping husk groups, so the ~4 husk groups (only `main`) PASS the gate: the gate does not catch them yet.

**Next:**
1. Run step 2 on `CWE416_groups` (same command as CWE415, in `prompt_pipeline/README.md`).
2. Check that the 6 husk groups (only `main`) are reported/excluded; compare with `claude_reference/check_group.py`.
3. Then step 3: rename (start from `src/prototype_cg_rename.py`).


**Background:** `discussions/discussion_personal_mac_1.md` (long; §12 is the 21 Sep handoff).
