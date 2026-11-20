"""Tests for the Rust-backed Python verification API."""

import socket
from urllib.parse import urlsplit

import pytest

from url_jail import VerificationCase, VerificationReport, verify_fetcher


def test_verifier_reports_a_refusal_without_a_connection():
    def refuse(_url):
        raise RuntimeError("blocked")

    report = verify_fetcher(refuse)

    assert isinstance(report, VerificationReport)
    assert report.passed
    assert all(isinstance(case, VerificationCase) for case in report.cases)
    assert all(case.passed and case.connections == 0 for case in report.cases)


def test_verifier_fails_when_callback_connects_before_refusing():
    def connect_then_refuse(url):
        target = urlsplit(url)
        with socket.create_connection((target.hostname, target.port), timeout=1):
            pass
        raise RuntimeError("blocked too late")

    report = verify_fetcher(connect_then_refuse)

    assert not report.passed
    literal_loopback = next(case for case in report.cases if case.name == "literal_loopback")
    assert literal_loopback.refused and literal_loopback.connections >= 1


def test_verifier_rejects_async_callbacks():
    async def fetch(_url):
        raise RuntimeError("blocked")

    with pytest.raises(TypeError, match="must be synchronous"):
        verify_fetcher(fetch)
