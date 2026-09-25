# Project instructions

The user often forgets where they left off and cannot keep documentation by hand. Claude keeps the record.

## Where things are
- `STATUS.md` — the current state (Now / Last result / Next). Short, max ~15 lines. Shown automatically at session start.
- `runs/runs.jsonl` — every experiment run, written by `track.py`. `python3 track.py --last 10` to list.
- `git log` — history of code changes.
- `liza/discussions/discussion_personal_mac_1.md` — long background discussion; not the current state.

## Rules for Claude
0. **`scripts/` is NOT the user's folder** — it belongs to another project. Never add, update, create, move or delete anything inside `scripts/` (reading and running is fine). Put any new code elsewhere, and only after the user says yes. Enforced by `.claude/settings.json` (deny rules + `protect_scripts.py` hook).
1. **Run experiments through `track.py`:** `uv run python track.py --note "<why>" -- <command>`. Suggest this to the user too.
2. **Update `STATUS.md` before ending any session where something changed** (code written, a run finished, a decision made). Replace old content; keep it short; put the date in the heading. Move nothing into long prose.
3. **Offer a git commit when a step works** (tests pass or a run succeeds). Conventional Commits, message written by Claude. Commit `runs/runs.jsonl` and `STATUS.md` with it.
4. The user wants to build the pipeline code themselves, step by step, with plain-language guidance. Don't write pipeline code for them unless asked.
