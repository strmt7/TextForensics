"""Kill tests for the W4 mutation-proof survivors in
``textforensics.emergency_stop._path_is_active``.

Worker F2 (audit W4): the cosmic-ray proof of the W4-changed
``_path_is_active`` (S08 fail-closed sentinel paths) left 3 survivors,
all in the ``None`` / ``OSError`` branches no existing test reaches
(the public tests drive ``check_emergency_stop``, which returns
``False`` before consulting ``_path_is_active`` when nothing is
configured, and never produces an un-stat-able path):

- ``[71, 15]`` ``ReplaceFalseWithTrue`` occ 0 — ``return False`` (no
  sentinel configured) -> ``return True``.
- ``[74, 11]`` ``ExceptionReplacer`` occ 1 — ``except OSError:`` ->
  ``except CosmicRayTestingException:`` (handler never matches, so an
  ``OSError`` from ``sentinel.exists()`` escapes instead of
  returning ``True``).
- ``[75, 15]`` ``ReplaceTrueWithFalse`` occ 1 — ``return True`` in the
  ``OSError`` handler -> ``return False``.

The ``OSError`` handler is exercised with a patched ``Path.exists``
because CPython's ``Path.exists()`` swallows ``OSError`` (returns
``False``) instead of raising it; the handler exists for the
documented fail-closed contract ("an un-stat-able path counts as
active") and for non-POSIX/stat behaviours, so the patch drives the
exact condition the handler is written for.
"""

import unittest
from unittest.mock import patch

from textforensics.emergency_stop import _path_is_active


class TestPathIsActiveSurvivors(unittest.TestCase):
    def test_none_path_is_inactive(self):
        """No sentinel configured -> not active (kills
        ReplaceFalseWithTrue [71, 15] occ 0)."""
        self.assertIs(_path_is_active(None), False)

    def test_oserror_from_exists_is_active_fail_closed(self):
        """An un-stat-able sentinel path counts as active (kills
        ExceptionReplacer [74, 11] occ 1 and ReplaceTrueWithFalse
        [75, 15] occ 1)."""
        with patch("pathlib.Path.exists", side_effect=OSError("stat failed")):
            self.assertIs(_path_is_active("/tmp/does-not-matter"), True)


if __name__ == "__main__":
    unittest.main()
