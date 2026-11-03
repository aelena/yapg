"""REST API tests via sanic-testing. Skipped when sanic is not installed."""

from __future__ import annotations

import pytest

sanic = pytest.importorskip("sanic")
pytest.importorskip("sanic_testing")

from keygen.server import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    from sanic_testing.testing import SanicTestClient

    return SanicTestClient(app)


def test_health(client):
    _, r = client.get("/health")
    assert r.status == 200 and r.json["status"] == "ok"


def test_api_key_json(client):
    _, r = client.get("/api-key?format=hex&length=32&count=3&prefix=pk_")
    assert r.status == 200
    assert r.json["count"] == 3
    assert all(k.startswith("pk_") and len(k) == 35 for k in r.json["keys"])


def test_api_key_bad_params(client):
    assert client.get("/api-key?format=rot13")[1].status == 400
    assert client.get("/api-key?length=abc")[1].status == 400
    assert client.get("/api-key?count=501")[1].status == 400
    assert client.get("/api-key?prefix=has%20space")[1].status == 400


def test_password_download(client):
    _, r = client.get("/password?count=5&download=1")
    assert r.status == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert "attachment; filename=\"passwords-" in r.headers["content-disposition"]
    assert len(r.text.strip().splitlines()) == 5


def test_password_no_classes(client):
    _, r = client.get("/password?upper=0&lower=0&digits=0&symbols=0")
    assert r.status == 400


def test_passphrase_pin_recovery(client):
    _, r = client.get("/passphrase?words=4&sep=.")
    assert r.status == 200 and r.json["entropy_bits"] > 50
    _, r = client.get("/pin?length=4&count=2")
    assert r.status == 200 and all(p.isdigit() and len(p) == 4 for p in r.json["pins"])
    _, r = client.get("/recovery-codes?count=3&length=12&groups=3")
    assert r.status == 200 and all(c.count("-") == 2 for c in r.json["codes"])
