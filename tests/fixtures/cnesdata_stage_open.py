"""Boundary fake for the keeper's stage-open publication (stage_wait); the real one has its own tests."""
import pytest


@pytest.fixture(autouse=True)
def stage_open_published(monkeypatch):
    from tools.cnesdata_delivery import application_gate as gate
    class Calls(list):
        original = None

    calls = Calls()
    original = gate._publish_stage_open
    monkeypatch.setattr(gate, "_publish_stage_open", lambda *args: calls.append(args))
    calls.original = original
    return calls
