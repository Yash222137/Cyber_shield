# Pattern Engine for signature-based detection
import json
import os
import logging
from typing import Dict, Any

logger = logging.getLogger("PatternEngine")

class PatternEngine:
    def __init__(self, rules_path: str = "./config/threat_rules.json"):
        self.rules_path = rules_path
        self.rules = self._load_rules()

    def _load_rules(self) -> Dict[str, Any]:
        if os.path.exists(self.rules_path):
            try:
                with open(self.rules_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading threat rules: {e}")
        return {"signatures": []}

    def scan_log_line(self, line: str) -> Dict[str, Any]:
        line_lower = line.lower()
        for rule in self.rules.get("signatures", []):
            pattern = rule.get("pattern", "").lower()
            if pattern and pattern in line_lower:
                return {
                    "matched": True,
                    "rule_name": rule.get("name", "Unknown Rule"),
                    "severity": rule.get("severity", "Medium")
                }
        return {"matched": False}
