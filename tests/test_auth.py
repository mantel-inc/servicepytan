"""Tests for servicepytan.auth module."""

import unittest
from unittest.mock import patch, MagicMock

from servicepytan.auth import request_auth_token


class TestRequestAuthTokenSecretMasking(unittest.TestCase):
    """Ensure client_secret is never leaked in error logs."""

    def test_client_secret_is_masked_in_warning_logs(self):
        """When token fetch fails, the logged message must not contain the raw secret."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.raise_for_status.side_effect = Exception("401 Unauthorized")
        mock_response.content = b""
        mock_response.text = ""

        with patch("servicepytan.auth.requests.post", return_value=mock_response), \
             self.assertLogs("servicepytan.auth", level="WARNING") as log_ctx:
            try:
                request_auth_token("https://example.com", "my_client_id", "SUPERSECRET", retry_count=1)
            except Exception:
                pass

        full_output = "\n".join(log_ctx.output)
        self.assertNotIn("SUPERSECRET", full_output)
        self.assertIn("********", full_output)
        self.assertIn("my_client_id", full_output)

    def test_client_secret_is_masked_when_no_response(self):
        """When the request itself raises (no response object), the secret must still be masked."""
        with patch("servicepytan.auth.requests.post", side_effect=ConnectionError("timeout")), \
             self.assertLogs("servicepytan.auth", level="WARNING") as log_ctx:
            try:
                request_auth_token("https://example.com", "my_client_id", "TOPSECRET", retry_count=1)
            except Exception:
                pass

        full_output = "\n".join(log_ctx.output)
        self.assertNotIn("TOPSECRET", full_output)
        self.assertIn("********", full_output)


if __name__ == "__main__":
    unittest.main()
