import unittest
import sys
import os
import time

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.defense.firewall_manager import FirewallManager


class TestFirewall(unittest.TestCase):
    def setUp(self):
        self.firewall = FirewallManager()

    def test_layer1_ip_filtering(self):
        self.assertFalse(self.firewall.is_ip_blocked("192.168.1.50"))
        
        self.assertTrue(self.firewall.block_ip("192.168.1.50"))
        self.assertTrue(self.firewall.is_ip_blocked("192.168.1.50"))
        
        # Second block returns False since already blocked
        self.assertFalse(self.firewall.block_ip("192.168.1.50"))
        
        self.assertTrue(self.firewall.unblock_ip("192.168.1.50"))
        self.assertFalse(self.firewall.is_ip_blocked("192.168.1.50"))

    def test_layer2_port_filtering(self):
        self.assertFalse(self.firewall.is_port_blocked(80))
        
        self.assertTrue(self.firewall.block_port(80))
        self.assertTrue(self.firewall.is_port_blocked(80))
        
        self.assertTrue(self.firewall.unblock_port(80))
        self.assertFalse(self.firewall.is_port_blocked(80))

    def test_layer3_payload_inspection_sqli(self):
        # Clean request
        res = self.firewall.inspect_payload("GET /profile?id=123 HTTP/1.1")
        self.assertTrue(res["clean"])
        self.assertIsNone(res["detected_attack"])

        # SQL Injection patterns
        res_sqli = self.firewall.inspect_payload("SELECT * FROM users WHERE username = 'admin' OR '1'='1'")
        self.assertFalse(res_sqli["clean"])
        self.assertEqual(res_sqli["detected_attack"], "SQL Injection")
        self.assertEqual(res_sqli["severity"], 85)

    def test_layer3_payload_inspection_xss(self):
        res_xss = self.firewall.inspect_payload("GET /search?q=<script>alert(1)</script>")
        self.assertFalse(res_xss["clean"])
        self.assertEqual(res_xss["detected_attack"], "Cross-Site Scripting (XSS)")

    def test_layer3_payload_inspection_path_traversal(self):
        res_pt = self.firewall.inspect_payload("GET /download?file=../../../../etc/passwd")
        self.assertFalse(res_pt["clean"])
        self.assertEqual(res_pt["detected_attack"], "Path Traversal")

    def test_layer3_payload_inspection_command_injection(self):
        res_ci = self.firewall.inspect_payload("ping 127.0.0.1; rm -rf /")
        self.assertFalse(res_ci["clean"])
        self.assertEqual(res_ci["detected_attack"], "Command Injection")

    def test_layer4_process_verification(self):
        # Authorized SSH port binding
        self.assertTrue(self.firewall.verify_process(1234, "sshd", 22))
        
        # Unauthorized database port binding by suspicious script
        self.assertFalse(self.firewall.verify_process(5678, "python3", 3306))

    def test_layer5_behavioral_rate_limiter(self):
        ip = "192.168.1.10"
        
        # Rapid connections below limit (e.g. 5 requests)
        for _ in range(5):
            self.assertTrue(self.firewall.track_traffic(ip, limit=10, window_seconds=2.0))
            
        # Exceeding limit (e.g. 6 more requests)
        blocked = False
        for _ in range(6):
            if not self.firewall.track_traffic(ip, limit=10, window_seconds=2.0):
                blocked = True
                
        self.assertTrue(blocked)
        self.assertTrue(self.firewall.is_ip_blocked(ip))


if __name__ == "__main__":
    unittest.main()
