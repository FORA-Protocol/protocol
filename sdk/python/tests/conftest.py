"""The pytest fixtures the Python SDK suites share.

pytest discovers a shared fixture from a conftest.py, so the fixtures live here and the
rest of the shared test code lives in the ``harness`` package. ``ssrf_env`` clears the
SSRF environment for one test. This file imports nothing from `fora_sdk`, so it never
masks the module-missing red the suites are meant to surface.
"""

from __future__ import annotations

import pytest

# What decides a resolver's transport outcome from the environment, and so what a test of
# that outcome must not inherit from the shell that runs it. SKIP_SSRF and ALLOW_INSECURE
# are the two flags the guarded clients read. The proxy variables are read by the plain
# client (``default_client`` leaves httpx's ``trust_env`` on, and httpx reads them through
# ``urllib.request.getproxies``, in either case), so a developer's proxy could otherwise
# carry a plain-client request. The guarded clients set ``trust_env=False`` and read none.
SSRF_ENV = (
    "SKIP_SSRF",
    "ALLOW_INSECURE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


@pytest.fixture
def ssrf_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    """Clear every variable in ``SSRF_ENV`` for one test and return ``monkeypatch``, so a
    test that needs a flag sets it after this fixture has run. ``monkeypatch`` restores
    the shell's values afterwards."""
    for name in SSRF_ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch
