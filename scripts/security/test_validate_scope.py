from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path
from types import ModuleType

SCRIPT_PATH = Path(__file__).with_name("validate_scope.py")
RECORD_PATH = (
    Path(__file__).parents[2]
    / "docs/security-program/engagements/ENG-0001/authorization-scope.json"
)


def _load_validator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("validate_scope", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load the scope validator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load_validator()


class ScopeValidationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.record = VALIDATOR.load_scope(RECORD_PATH)

    def test_committed_scope_is_valid(self) -> None:
        self.assertEqual(VALIDATOR.validate_scope(self.record), [])

    def test_external_endpoint_is_rejected(self) -> None:
        record = copy.deepcopy(self.record)
        record["targets"][0]["endpoint"] = "https://example.com"
        errors = VALIDATOR.validate_scope(record)
        self.assertIn("targets[0].endpoint is not loopback-only", errors)

    def test_real_data_permission_is_rejected(self) -> None:
        record = copy.deepcopy(self.record)
        record["data_rules"]["real_customer_data_allowed"] = True
        errors = VALIDATOR.validate_scope(record)
        self.assertIn("real_customer_data_allowed must be false", errors)

    def test_unbounded_limit_is_rejected(self) -> None:
        record = copy.deepcopy(self.record)
        record["limits"]["max_concurrent_requests"] = 0
        errors = VALIDATOR.validate_scope(record)
        self.assertIn(
            "limits.max_concurrent_requests must be a positive integer", errors
        )


if __name__ == "__main__":
    unittest.main()
