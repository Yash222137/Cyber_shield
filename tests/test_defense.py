import unittest
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.defense.ip_blocker import IPBlocker
from core.defense.process_killer import ProcessKiller

class TestDefense(unittest.TestCase):
    def test_ip_blocker_sandboxed(self):
        blocker = IPBlocker()
        res = blocker.block_ip("192.168.1.1")
        self.assertTrue(res)

    def test_process_killer_sandboxed(self):
        killer = ProcessKiller()
        res = killer.kill_process(1234)
        self.assertTrue(res)

if __name__ == "__main__":
    unittest.main()
