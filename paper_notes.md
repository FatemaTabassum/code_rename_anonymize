# Notes for the paper

Method details worth reporting, collected as they come up. Newest at the bottom.

## Juliet support headers (2026-09-26)

**What:** Every Juliet test file starts with `#include "std_testcase.h"`. This is a shared Juliet helper header, not part of any test case. It pulls in `std_testcase_io.h` (declarations of helpers such as `printLine`) and the standard C/C++ headers. The step 2 gate compiles every file, so it has to find this header.

**What we did:** Copied the four Juliet support headers into `prompt_pipeline/juliet_support/` and compiled every file with `-I prompt_pipeline/juliet_support`. Before this, the gate pointed to a copy inside a different local project.

**Where they came from:** `renaming_folder/juliet/CWE190/source_files/`. This was the only copy on the machine; the CWE-415/416 source folders do not contain one. The headers are shared across all CWEs in Juliet, so taking them from the CWE-190 folder does not change anything for CWE-415/416.

SHA-256 of the copied files (identical to the source copies):

| File | SHA-256 |
|---|---|
| `std_testcase.h` | `a78aaf3a54a6210260ad70123c09c3c283c6edf7808b6244205e00b8f2d9b8d0` |
| `std_testcase_io.h` | `6459df50d22697bb61619e2effd688ebb98915db25f7eb1bdbb767f888066fb6` |
| `std_thread.h` | `3a0512cfccb90e30811399876066c23077be53990f57f205749a6a591a7eee5a` |
| `testcases.h` | `205611043d584ef88754b3d3512e3b61d4994b1b7e2cce0b03d825ef5f996e2c` |

**Only headers are used:** The helper source files that define these functions (`io.c`, `std_thread.c`) are not used. The gate compiles each file on its own (`-c`) and does not build a full program, so only declarations are needed. The gate counts a symbol as part of the test case only if its name contains `CWE<digit>` (`PROJECT_RE` in `src/step_2_gate.py`). Juliet helpers such as `printLine` do not match, so they are treated as outside the test case, the same way as libc calls.

**Open for the paper:** Which Juliet release these headers came from (e.g. v1.3) has not been confirmed yet. Check this against the download before citing.

**Possible paper wording:** "Each test file was compiled with the Juliet test-suite support headers (`std_testcase.h` and its includes) on the include path; the support implementation files were not linked, since the gate checks each file in isolation."
