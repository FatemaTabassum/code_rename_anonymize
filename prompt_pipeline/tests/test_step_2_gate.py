"""
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


"""




"""Regression tests for src/step_2_gate.py."""
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from step_2_gate import CHECKS, check_group, gate_groups  # noqa: E402


def write(path: Path, content: str) -> None:
    path.write_text(content)


class CheckGroupTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.group_dir = Path(self.tmp.name) / "group"
        self.group_dir.mkdir()
        self.obj_dir = Path(self.tmp.name) / "obj"
        self.obj_dir.mkdir()

    def run_check(self):
        return check_group(self.group_dir, includes=[], obj_dir=self.obj_dir)

    def test_pass_two_linked_pieces_one_main(self):
        write(self.group_dir / "a.c", """
void CWE415_test_bad(void);
extern void CWE415_test_sink(void);

void CWE415_test_bad(void) {
    CWE415_test_sink();
}

int main(void) {
    CWE415_test_bad();
    return 0;
}
""")
        write(self.group_dir / "b.c", """
void CWE415_test_sink(void) {
}
""")
        res = self.run_check()
        for c in CHECKS:
            self.assertIs(res[c], True, f"{c} should pass: {res['notes']}")

    def test_compile_error_fails_compiles_and_undetermines_rest(self):
        write(self.group_dir / "broken.c", "int main() { return }")
        res = self.run_check()
        self.assertIs(res["COMPILES"], False)
        for c in ("CLOSED", "NO_DUP_DEF", "CONNECTED", "ONE_MAIN"):
            self.assertIsNone(res[c])

    def test_missing_definition_fails_closed(self):
        # Sink is declared and called but never defined anywhere in the group.
        write(self.group_dir / "a.c", """
extern void CWE415_test_sink(void);

void CWE415_test_bad(void) {
    CWE415_test_sink();
}

int main(void) {
    CWE415_test_bad();
    return 0;
}
""")
        res = self.run_check()
        self.assertIs(res["COMPILES"], True)
        self.assertIs(res["CLOSED"], False)

    def test_two_mains_fails_one_main(self):
        write(self.group_dir / "a.c", "int main(void) { return 0; }")
        write(self.group_dir / "b.c", "int main(void) { return 0; }")
        res = self.run_check()
        self.assertIs(res["ONE_MAIN"], False)

    def test_duplicate_definition_fails_no_dup_def(self):
        write(self.group_dir / "a.c", "void CWE415_test_bad(void) {}")
        write(self.group_dir / "b.c", "void CWE415_test_bad(void) {}")
        res = self.run_check()
        self.assertIs(res["NO_DUP_DEF"], False)

    def test_vtable_only_linkage_still_counts_as_connected(self):
        # Mirrors real CWE415 variant 81: a driver builds a subclass and
        # calls a pure-virtual method through a base reference. The call is
        # indirect (vtable dispatch), so the driver never directly
        # references the sink's mangled symbol by name -- the only thing
        # tying the pieces together is the vtable/typeinfo linkage. Per
        # others/code_juliet/README.md, this must still count as CONNECTED.
        write(self.group_dir / "shared.h", """
class CWE415_Base {
public:
    virtual void action(int * data) const = 0;
};
class CWE415_Bad : public CWE415_Base {
public:
    void action(int * data) const;
};
""")
        write(self.group_dir / "driver.cpp", """
#include "shared.h"
int main(void) {
    int x = 0;
    const CWE415_Base& b = CWE415_Bad();
    b.action(&x);
    return 0;
}
""")
        write(self.group_dir / "sink.cpp", """
#include "shared.h"
void CWE415_Bad::action(int * data) const {
}
""")
        res = self.run_check()
        self.assertIs(res["COMPILES"], True, res["notes"])
        self.assertIs(res["CONNECTED"], True, res["notes"])


class GateGroupsTest(unittest.TestCase):
    def test_gate_groups_walks_omit_type_and_group_dirs(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            pass_dir = root / "omitbad" / "CWE415_x_01"
            pass_dir.mkdir(parents=True)
            write(pass_dir / "a.c", "int main(void) { return 0; }")

            fail_dir = root / "omitgood" / "CWE415_x_01"
            fail_dir.mkdir(parents=True)
            write(fail_dir / "a.c", "int main() { return }")

            with tempfile.TemporaryDirectory() as objroot:
                results = gate_groups(root, includes=[], obj_root=Path(objroot), jobs=2)

        self.assertEqual(len(results), 2)
        by_group = {r["group"]: r for r in results}
        self.assertTrue(all(by_group["omitbad/CWE415_x_01"][c] is True for c in CHECKS))
        self.assertIs(by_group["omitgood/CWE415_x_01"]["COMPILES"], False)


if __name__ == "__main__":
    unittest.main()
