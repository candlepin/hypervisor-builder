"""Prefer the in-tree hypervisor package over any installed copy.

The library is often pip-installed in the same environment that runs
these tests (it is a dependency of its consumers); without this shim a
bare ``pytest`` invocation would import the installed copy instead of
the checkout under test.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
