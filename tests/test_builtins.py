from vantage.scanning.builtins import build_default_registry


def test_default_registry_contains_cloudsentry():
    registry = build_default_registry()
    assert registry.get("cloudsentry").supports_active_checks is False
