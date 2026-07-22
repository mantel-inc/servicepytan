"""Tests for servicepytan.auth module."""

from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch, MagicMock

from servicepytan.auth import (
    ApiEnvironment,
    ServiceTitanConnection,
    get_auth_token,
    invalidate_auth_token,
    request_auth_token,
    servicepytan_connect,
)


def make_connection():
    return ServiceTitanConnection({
        "SERVICETITAN_CLIENT_ID": "client-id",
        "SERVICETITAN_CLIENT_SECRET": "client-secret",
        "SERVICETITAN_APP_KEY": "app-key",
        "SERVICETITAN_TENANT_ID": "tenant-id",
        "auth_root": "https://auth.example.com",
        "api_root": "https://api.example.com",
    })


class TestAuthTokenCaching(unittest.TestCase):
    def test_servicepytan_connect_returns_dict_compatible_connection(self):
        conn = servicepytan_connect(
            api_environment=ApiEnvironment.INTEGRATION,
            app_key="app-key",
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",
        )

        self.assertIsInstance(conn, dict)
        self.assertIsInstance(conn, ServiceTitanConnection)
        self.assertEqual(conn["SERVICETITAN_TENANT_ID"], "tenant-id")
        self.assertNotIn("_auth_token", conn)

    @patch("servicepytan.auth.request_auth_token")
    def test_reuses_token_until_safety_window(self, mock_request_auth_token):
        mock_request_auth_token.side_effect = [
            {"access_token": "token-one", "expires_in": 900},
            {"access_token": "token-two", "expires_in": 900},
        ]
        conn = make_connection()

        with patch("servicepytan.auth.time.monotonic") as monotonic:
            monotonic.return_value = 100
            self.assertEqual(get_auth_token(conn), "token-one")

            # A 900-second token is considered stale 60 seconds early.
            monotonic.return_value = 939
            self.assertEqual(get_auth_token(conn), "token-one")

            monotonic.return_value = 940
            self.assertEqual(get_auth_token(conn), "token-two")

        self.assertEqual(mock_request_auth_token.call_count, 2)

    @patch("servicepytan.auth.request_auth_token")
    def test_concurrent_first_use_fetches_one_token(self, mock_request_auth_token):
        mock_request_auth_token.return_value = {
            "access_token": "shared-token",
            "expires_in": 900,
        }
        conn = make_connection()

        with ThreadPoolExecutor(max_workers=10) as executor:
            tokens = list(executor.map(lambda _: get_auth_token(conn), range(20)))

        self.assertEqual(tokens, ["shared-token"] * 20)
        mock_request_auth_token.assert_called_once()

    @patch("servicepytan.auth.request_auth_token")
    def test_concurrent_expiry_refreshes_once(self, mock_request_auth_token):
        mock_request_auth_token.return_value = {
            "access_token": "refreshed-token",
            "expires_in": 900,
        }
        conn = make_connection()
        conn._auth_token = "expired-token"
        conn._auth_token_valid_until = 0

        with ThreadPoolExecutor(max_workers=10) as executor:
            tokens = list(executor.map(lambda _: get_auth_token(conn), range(20)))

        self.assertEqual(tokens, ["refreshed-token"] * 20)
        mock_request_auth_token.assert_called_once()

    @patch("servicepytan.auth.request_auth_token")
    def test_failed_refresh_does_not_poison_cache(self, mock_request_auth_token):
        mock_request_auth_token.side_effect = [
            RuntimeError("auth unavailable"),
            {"access_token": "recovered-token", "expires_in": 900},
        ]
        conn = make_connection()

        with self.assertRaisesRegex(RuntimeError, "auth unavailable"):
            get_auth_token(conn)

        self.assertIsNone(conn._auth_token)
        self.assertEqual(get_auth_token(conn), "recovered-token")

    def test_stale_401_does_not_invalidate_newer_token(self):
        conn = make_connection()
        conn._auth_token = "new-token"
        conn._auth_token_valid_until = float("inf")

        invalidate_auth_token(conn, rejected_token="old-token")

        self.assertEqual(conn._auth_token, "new-token")


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

    def test_token_response_is_not_written_to_error_log(self):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.side_effect = ValueError("invalid json")
        mock_response.content = b'{"access_token":"TOKEN_FROM_RESPONSE"}'
        mock_response.text = mock_response.content.decode()

        with patch("servicepytan.auth.requests.post", return_value=mock_response), \
             self.assertLogs("servicepytan.auth", level="WARNING") as log_ctx:
            with self.assertRaises(ValueError):
                request_auth_token(
                    "https://example.com", "my_client_id", "SUPERSECRET", retry_count=1,
                )

        full_output = "\n".join(log_ctx.output)
        self.assertNotIn("TOKEN_FROM_RESPONSE", full_output)
        self.assertNotIn("SUPERSECRET", full_output)


if __name__ == "__main__":
    unittest.main()
