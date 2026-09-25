"""Regression tests for src/step_1_grouping.py grouping logic."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from step_1_grouping import group_files  # noqa: E402

STEM = "CWE415_Double_Free__no_copy_const"


class GroupFilesTest(unittest.TestCase):
    def test_lettered_pieces_of_one_variant_share_a_group(self):
        names = [f"{STEM}_53a_omitgood.c", f"{STEM}_53b_omitgood.c"]
        groups = group_files(names)
        self.assertEqual(groups, {(STEM, "53", "omitgood"): names})

    def test_named_piece_joins_group_when_a_lettered_piece_exists(self):
        # Mirrors CWE415 variant 81: 81a (lettered) plus 81_bad (named) belong
        # to one compiled unit and must land in the same group.
        names = [f"{STEM}_81a_omitbad.cpp", f"{STEM}_81_bad_omitbad.cpp"]
        groups = group_files(names)
        self.assertEqual(len(groups), 1, f"expected 1 group, got {groups}")
        self.assertEqual(sorted(next(iter(groups.values()))), sorted(names))

    def test_standalone_named_pieces_do_not_merge_into_one_group(self):
        # Regression for the real CWE415 bug: no_copy_const_01_bad and
        # no_copy_const_01_good1 are two independent files that each define
        # their own main(). With no lettered piece for (stem, "01"), they
        # must NOT be merged into a single ("01", omitbad) group -- that
        # would put two main()s in one sample.
        bad = f"{STEM}_01_bad_omitbad.cpp"
        good1 = f"{STEM}_01_good1_omitbad.cpp"
        groups = group_files([bad, good1])

        self.assertEqual(len(groups), 2, f"expected 2 separate groups, got {groups}")
        all_names = [name for names in groups.values() for name in names]
        self.assertEqual(sorted(all_names), sorted([bad, good1]))
        for names in groups.values():
            self.assertEqual(len(names), 1)


if __name__ == "__main__":
    unittest.main()
