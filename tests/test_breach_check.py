"""Tests for the breach detection service."""

import hashlib
from unittest.mock import patch, MagicMock
from services.breach_check import check_password_breach


class TestBreachCheck:
    """Test HIBP k-anonymity breach checking."""

    @patch('services.breach_check.requests.get')
    def test_known_breached_password(self, mock_get):
        """'password' is a known breached password — should return True."""
        # SHA-1 of 'password' = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        # prefix = 5BAA6, suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        sha1 = hashlib.sha1(b'password').hexdigest().upper()
        suffix = sha1[5:]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = (
            f"0018A45C4D1DEF81644B54AB7F969B88D65:1\n"
            f"{suffix}:3861493\n"
            f"00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n"
        )
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        is_breached, count = check_password_breach("password")

        assert is_breached is True
        assert count == 3861493
        mock_get.assert_called_once()
        call_url = mock_get.call_args[0][0]
        assert call_url.endswith("/5BAA6")

    @patch('services.breach_check.requests.get')
    def test_safe_password(self, mock_get):
        """A random password not in the response should return False."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = (
            "0018A45C4D1DEF81644B54AB7F969B88D65:1\n"
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2\n"
            "011053FD0102E94D6AE2F8B83D76FAF94F6:3\n"
        )
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        is_breached, count = check_password_breach("xK9#mQ!zR@pL7vN&wY2")

        assert is_breached is False
        assert count == 0

    @patch('services.breach_check.requests.get')
    def test_network_error_raises(self, mock_get):
        """Network failures should propagate as exceptions."""
        import requests as req
        mock_get.side_effect = req.ConnectionError("No internet")

        try:
            check_password_breach("test")
            assert False, "Should have raised"
        except req.ConnectionError:
            pass  # Expected

    @patch('services.breach_check.requests.get')
    def test_prefix_is_5_chars(self, mock_get):
        """Only the first 5 hex characters of SHA-1 should be sent."""
        mock_response = MagicMock()
        mock_response.text = ""
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response

        check_password_breach("anything")

        call_url = mock_get.call_args[0][0]
        prefix_in_url = call_url.split("/")[-1]
        assert len(prefix_in_url) == 5
