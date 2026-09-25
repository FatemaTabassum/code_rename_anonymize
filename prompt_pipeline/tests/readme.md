There are 10 tests, 3 for step 1 and 7 for step 2.

What a test is: a tiny made-up example with a known right answer. The test runs your code on the example and checks it gives that answer. If you later change the code and break something, a test fails and tells you straight away.

Run them all from the repo root with:
uv run python track.py --note "run tests" -- uv run --no-project --with pytest python -m pytest -q prompt_pipeline/tests









Step 1 tests: test_step_1_grouping.py

All three feed a list of file names to group_files() and check which files end up together. No real files are needed, since grouping uses only the names.

Test 1: lettered pieces of one test case go together (line 14)
- Input: ..._53a_omitgood.c and ..._53b_omitgood.c
- Expected: one group, (stem, "53", "omitgood"), holding both files in order a, b.
- Why: in Juliet, 53a, 53b and so on are pieces of one program split across files.

Test 2: a named piece joins the lettered pieces (line 19)
- Input: ..._81a_omitbad.cpp and ..._81_bad_omitbad.cpp
- Expected: one group with both files.
- Why: in real test case 81, the 81_bad file belongs to the same program as 81a. If it were split off, the sample would be missing code.

Test 3: two stand-alone files must NOT be merged (line 27)
- Input: ..._01_bad_omitbad.cpp and ..._01_good1_omitbad.cpp
- Expected: two separate groups, one file each.
- Why: this is a real bug that was found and fixed. Each of these files is its own complete program with its own main(). Merging them put two main()s in one sample. The test makes sure that bug can't come back.







Step 2 tests: test_step_2_gate.py

These write tiny C/C++ files into a temporary folder that is deleted afterwards. They run the gate on that folder and check the gate's verdict. The gate has 5 checks:

┌────────────┬───────────────────────────────────────────────────────────────────┐
│   Check    │                           Plain meaning                           │
├────────────┼───────────────────────────────────────────────────────────────────┤
│ COMPILES   │ every file compiles on its own                                    │
├────────────┼───────────────────────────────────────────────────────────────────┤
│ CLOSED     │ every function the group calls is defined somewhere in the group  │
├────────────┼───────────────────────────────────────────────────────────────────┤
│ NO_DUP_DEF │ no function is defined twice                                      │
├────────────┼───────────────────────────────────────────────────────────────────┤
│ CONNECTED  │ the files link to each other as one program, not unrelated pieces │
├────────────┼───────────────────────────────────────────────────────────────────┤
│ ONE_MAIN   │ at most one main()                                                │
└────────────┴───────────────────────────────────────────────────────────────────┘

Test 4: a good group passes everything (line 28)
- a.c has main, which calls bad(), which calls sink(). b.c defines sink().
- Expected: all 5 checks pass. This proves the gate doesn't reject correct groups.

Test 5: broken code (line 50)
- One file, int main() { return }, with a syntax error.
- Expected: COMPILES = fail, and the other 4 = None. None means "couldn't check", because once a file doesn't compile the gate can't inspect it, so it reports "unknown" rather than guessing.

Test 6: a missing piece (line 57)
- sink() is called but no file defines it. This is what a group looks like if a file like 53c got lost.
- Expected: COMPILES passes (each file compiles on its own) but CLOSED fails.

Test 7: two main()s (line 75)
- Expected: ONE_MAIN fails. This is the step 2 guard against the same bug as Test 3.

Test 8: the same function defined twice (line 81)
- Expected: NO_DUP_DEF fails. This catches a file copied into a group twice.

Test 9: C++ files linked only through a class (line 87)
- driver.cpp calls action() through a base-class reference, and sink.cpp defines CWE415_Bad::action. The driver never names the sink function directly; the files are linked only through the C++ class machinery (the vtable).
- Expected: CONNECTED passes.
- Why: this copies real test case 81. A simpler gate would wrongly call these files "unrelated" and reject a good group.

Test 10: the gate walks the whole output folder (line 124)
- Builds a fake step 1 output with omitbad/CWE415_x_01 (fine) and omitgood/CWE415_x_01 (broken), then runs gate_groups() on the top folder.
- Expected: exactly 2 results, the first passing everything and the second failing COMPILES. This checks that the gate finds every group in the real folder layout and doesn't mix up the two omit types.











What the tests don't cover

1. The 6 "husk" groups, which contain only main(). That's the known open defect, and no test checks it. A husk group would pass all 5 checks today, because it compiles, is closed and has one main. That's why STATUS.md next step 2 says to check the husks.
2. Step 1 headers. Nothing tests that .h files are copied into the right groups.
3. Separating omitgood from omitbad in step 1. Nothing tests that the same number with different omit types gives two groups.

These gaps are good places for you to write your own first tests. Gap 1 matters most, because it affects your sample counts (1,928 → 1,924 for CWE-415). If you want to try one, I'll guide you through writing it, and you write the code yourself.