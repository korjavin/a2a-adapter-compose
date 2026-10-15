"""Unit tests for dashboard.py."""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard import self_check


class DashboardTestCase(unittest.TestCase):
    def test_dashboard_self_check(self):
        self_check()


if __name__ == "__main__":
    unittest.main()
