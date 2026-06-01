"""
Shared pytest fixtures and helpers for SASTify test suite.
"""
import sys
import pytest

# Ensure Backend module is importable
sys.path.insert(0, 'Backend')

from enhanced_rule_engine import EnhancedRuleEngine
from framework_security_rules import FrameworkRuleEngine
from dataflow_graph import DataflowEnhancedScanner, analyze_function_taint


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner():
    """Return a fresh EnhancedRuleEngine instance for each test."""
    return EnhancedRuleEngine()


@pytest.fixture
def framework_scanner():
    """Return a fresh FrameworkRuleEngine instance for each test."""
    return FrameworkRuleEngine()


@pytest.fixture
def dataflow_scanner():
    """Return a fresh DataflowEnhancedScanner instance for each test."""
    return DataflowEnhancedScanner()


# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

def assert_has_vulnerability(issues, vuln_type, *, min_confidence=0.0):
    """Assert that *at least one* issue matches the given vulnerability type.

    Parameters
    ----------
    issues : list[dict]
        The list returned by a scanner's scan method.
    vuln_type : str
        Expected value for the ``type`` key in an issue dict.
    min_confidence : float, optional
        If provided, additionally checks that the matching issue's confidence
        is at least this value.
    """
    matching = [i for i in issues if i['type'] == vuln_type]
    assert matching, (
        f"Expected vulnerability '{vuln_type}' not found.\n"
        f"  Found types: {sorted(set(i['type'] for i in issues))}"
    )
    if min_confidence > 0:
        best = max(m['confidence'] for m in matching)
        assert best >= min_confidence, (
            f"Confidence for '{vuln_type}' is {best}, expected >= {min_confidence}"
        )


def assert_no_vulnerability(issues, vuln_type):
    """Assert that *no* issue matches the given vulnerability type."""
    matching = [i for i in issues if i['type'] == vuln_type]
    assert not matching, (
        f"Unexpected vulnerability '{vuln_type}' found at line(s): "
        f"{[m.get('line') for m in matching]}"
    )


def assert_vulnerability_count(issues, vuln_type, expected_count):
    """Assert exactly ``expected_count`` issues of the given type."""
    matching = [i for i in issues if i['type'] == vuln_type]
    assert len(matching) == expected_count, (
        f"Expected {expected_count} '{vuln_type}' issues, found {len(matching)}"
    )


def get_issues_of_type(issues, vuln_type):
    """Filter and return only issues matching the given type."""
    return [i for i in issues if i['type'] == vuln_type]
