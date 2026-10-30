"""Tests for password generator and breach checker."""

import pytest
from services.password_generator import (
    calculate_password_strength,
    generate_passphrase,
    generate_random_password,
)
from services.breach_check import BreachChecker


def test_generate_random_password():
    pwd = generate_random_password(length=20, upper=True, lower=True, digits=True, symbols=True)
    assert len(pwd) == 20
    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)


def test_generate_random_password_boundary():
    # Min length constraint
    pwd_short = generate_random_password(length=4)
    assert len(pwd_short) >= 8

    # All disabled fallback
    pwd_none = generate_random_password(length=12, upper=False, lower=False, digits=False, symbols=False)
    assert len(pwd_none) == 12


def test_generate_passphrase():
    phrase = generate_passphrase(word_count=4, separator="-", capitalize=True)
    words = phrase.split("-")
    assert len(words) == 4
    for w in words:
        assert w[0].isupper()


def test_breach_checker_cancel():
    checker = BreachChecker()
    checker.cancel()  # Should not raise
    checker.cancel()
