"""Shared test setup.

Unit tests need no database or Docker. A fresh key set is generated once per test session
with the real scripts/gen_keys.py, and `as_service("ballot")` points settings at that
service's key folder, exactly as it would see /run/keys inside its container.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_module(relative_path: str, name: str | None = None):
    """Import a service file by path (every service's package is called `app`)."""
    path = ROOT / relative_path
    name = name or "svc_" + relative_path.replace("/", "_").removesuffix(".py")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def keys_root(tmp_path_factory) -> Path:
    gen_keys = load_module("scripts/gen_keys.py", "gen_keys")
    out = tmp_path_factory.mktemp("keys")
    gen_keys.generate(out)
    return out


@pytest.fixture
def as_service(keys_root, monkeypatch):
    from common import keys, settings

    def switch(service: str):
        monkeypatch.setenv("SV_SERVICE_NAME", service)
        monkeypatch.setenv("SV_ENVIRONMENT", "test")
        monkeypatch.setenv("SV_KEYS_DIR", str(keys_root / service))
        settings.get_settings.cache_clear()
        keys.clear_cache()
        return settings.get_settings()

    yield switch
    settings.get_settings.cache_clear()
    keys.clear_cache()
