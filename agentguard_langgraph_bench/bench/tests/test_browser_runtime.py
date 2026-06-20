from pathlib import Path
from urllib.parse import urlparse

from agentguard_langgraph_bench.bench.browser_runtime import RealBrowserRuntime, RECORDER_SCRIPT


def test_strict_browser_runtime_allows_configured_local_service_port(tmp_path):
    runtime = RealBrowserRuntime(tmp_path, allowed_local_service_ports={18083})
    runtime._server = object()

    assert runtime._is_allowed_local_http(urlparse("http://127.0.0.1:18083/mail/send")) is True
    assert runtime._is_allowed_local_http(urlparse("http://127.0.0.1:65535/mail/send")) is False
    assert runtime._is_allowed_local_http(urlparse("https://example.com/")) is False


def test_strict_mode_does_not_prepare_page_unlock_script(tmp_path):
    runtime = RealBrowserRuntime(tmp_path, fixture_compat_mode="strict")

    class Page:
        called = False

        def evaluate(self, _script):
            self.called = True

    class Session:
        page = Page()

    runtime._prepare_page_for_action(Session())

    assert Session.page.called is False


def test_legacy_mode_keeps_compatibility_unlock_available(tmp_path):
    runtime = RealBrowserRuntime(tmp_path, fixture_compat_mode="legacy")

    class Page:
        script = ""

        def evaluate(self, script):
            self.script = script

    class Session:
        page = Page()

    runtime._prepare_page_for_action(Session())

    assert "removeAttribute('readonly')" in Session.page.script
    assert "novalidate" in Session.page.script


def test_recorder_redacts_password_values():
    assert 'type === "password" ? ""' in RECORDER_SCRIPT
    assert "value_present" in RECORDER_SCRIPT
    assert "value_length" in RECORDER_SCRIPT
