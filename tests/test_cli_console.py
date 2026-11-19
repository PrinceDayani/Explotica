"""Tests for the CLI console colour/emoji fallback."""
import io

from explotica.cli import _build_console, _to_ascii, _Console


def test_to_ascii_replaces_known_glyphs():
    assert _to_ascii("✅ ok") == "[OK] ok"
    assert _to_ascii("🔴 crit ➜ ＋") == "[CRIT] crit -> +"


def test_no_color_console_strips_emoji():
    buf = io.StringIO()
    c = _Console(file=buf, no_color=True, emoji=False, ascii_only=True,
                 force_terminal=False)
    c.print("✅ done ⚠ warn")
    out = buf.getvalue()
    assert "✅" not in out and "⚠" not in out
    assert "[OK]" in out and "[!]" in out


def test_color_console_keeps_emoji():
    buf = io.StringIO()
    c = _Console(file=buf, ascii_only=False, force_terminal=True)
    c.print("✅ done")
    assert "✅" in buf.getvalue()


def test_build_console_env_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    c = _build_console()
    assert isinstance(c, _Console)
    assert c._ascii_only is True
