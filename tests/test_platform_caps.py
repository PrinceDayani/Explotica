"""Platform capability detection — Phase 66."""

from explotica.core.platform_caps import PlatformCaps, detect


class TestDetect:
    def test_returns_platform_caps(self):
        caps = detect()
        assert isinstance(caps, PlatformCaps)

    def test_os_name_consistent(self):
        caps = detect()
        # Exactly one of the OS flags is True (or we're on "other")
        flags = (caps.is_linux, caps.is_macos, caps.is_windows)
        assert sum(flags) <= 1

    def test_os_name_matches_flags(self):
        caps = detect()
        if caps.is_linux:
            assert caps.os_name == "linux"
        if caps.is_windows:
            assert caps.os_name == "windows"
        if caps.is_macos:
            assert caps.os_name == "darwin"

    def test_summary_is_string(self):
        caps = detect()
        s = caps.summary()
        assert isinstance(s, str)
        assert "Platform:" in s
        assert "Capability matrix:" in s


class TestPlatformSpecific:
    def test_windows_no_sigterm_or_uvloop(self):
        caps = detect()
        if caps.is_windows:
            # uvloop is Linux/macOS only
            assert not caps.has_uvloop

    def test_linux_can_have_ip_route(self):
        caps = detect()
        if caps.is_linux:
            # Most Linux distros have `ip` — but we don't require it
            # Just verify the flag is a bool
            assert isinstance(caps.has_ip_route, bool)

    def test_windows_route_print_flag_exists(self):
        caps = detect()
        if caps.is_windows:
            # Windows always has route.exe
            assert caps.has_route_print

    def test_root_flag_is_bool(self):
        caps = detect()
        assert isinstance(caps.is_root, bool)
