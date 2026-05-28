"""Scan checkpoint — Phase 63."""

import json
import tempfile
import time
from pathlib import Path

from explotica.checkpoint import Checkpoint
from explotica import shutdown


class TestCheckpoint:
    def test_disabled_when_no_path(self):
        chk = Checkpoint(None)
        assert not chk.enabled
        # Should be no-op
        chk.update({"x": 1})
        chk.finalize({"x": 1})

    def test_first_update_writes(self, tmp_path):
        path = tmp_path / "scan.json"
        chk = Checkpoint(path, every_n_hosts=1, every_secs=60)
        chk.update({"hosts": ["a"]})
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["hosts"] == ["a"]

    def test_throttles_subsequent_updates(self, tmp_path):
        path = tmp_path / "scan.json"
        # every_n=5 + every_secs=60: first update writes (because
        # _last_write=0 makes elapsed huge), then writes every 5th update
        chk = Checkpoint(path, every_n_hosts=5, every_secs=60)
        chk.update({"hosts": ["a"]})           # count=1, writes via elapsed
        first_mtime = path.stat().st_mtime
        time.sleep(0.01)
        chk.update({"hosts": ["a", "b"]})      # count=2, throttled
        assert path.stat().st_mtime == first_mtime
        # Updates 3, 4 throttled
        for _ in range(2):
            chk.update({"hosts": ["a", "b", "c"]})
        # Update 5 — triggers write (5 % 5 == 0)
        chk.update({"hosts": ["a", "b", "c", "d"]})
        data = json.loads(path.read_text())
        assert len(data["hosts"]) == 4

    def test_finalize_always_writes(self, tmp_path):
        path = tmp_path / "scan.json"
        chk = Checkpoint(path, every_n_hosts=1000)
        chk.update({"hosts": ["a"]})
        chk.update({"hosts": ["a", "b"]})
        # Without finalize, only the first write happened
        chk.finalize({"hosts": ["a", "b", "c"]})
        data = json.loads(path.read_text())
        assert len(data["hosts"]) == 3

    def test_atomic_write_uses_temp(self, tmp_path):
        path = tmp_path / "scan.json"
        chk = Checkpoint(path, every_n_hosts=1)
        chk.update({"hosts": ["a"]})
        # No .partial leftover after write
        assert not path.with_suffix(".json.partial").exists()

    def test_load_returns_none_for_missing(self, tmp_path):
        result = Checkpoint.load(tmp_path / "nonexistent.json")
        assert result is None

    def test_load_recovers_data(self, tmp_path):
        path = tmp_path / "scan.json"
        path.write_text(json.dumps({"target": "10.0.0.0/24", "x": 42}))
        data = Checkpoint.load(path)
        assert data["target"] == "10.0.0.0/24"
        assert data["x"] == 42

    def test_load_invalid_json_returns_none(self, tmp_path):
        path = tmp_path / "scan.json"
        path.write_text("not valid json {{{")
        assert Checkpoint.load(path) is None


class TestShutdownIntegration:
    def test_shutdown_token_flushes(self, tmp_path):
        shutdown.reset()
        path = tmp_path / "scan.json"
        chk = Checkpoint(path, every_n_hosts=1000)
        chk.update({"hosts": ["a", "b"]})
        # First write happened (update #1 always writes)
        # Now reset throttle by changing data
        chk._last_data = {"hosts": ["a", "b", "c"]}
        # Trigger shutdown — should flush
        shutdown.get_token().request("test")
        # Reload — should have the latest data
        data = json.loads(path.read_text())
        assert len(data["hosts"]) == 3
        shutdown.reset()
