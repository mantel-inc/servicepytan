"""Tests for servicepytan.auth module."""

from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest.mock import patch, MagicMock, mock_open

import requests

from servicepytan.auth import (
    AUTH_REQUEST_TIMEOUT_SECONDS,
    ApiEnvironment,
    ServiceTitanConnection,
    get_auth_token,
    invalidate_auth_token,
    request_auth_token,
    servicepytan_connect,
)


def make_connection():
    return ServiceTitanConnection(
        api_environment=ApiEnvironment.INTEGRATION,
        client_id="client-id",
        client_secret="client-secret",
        app_key="app-key",
        tenant_id="tenant-id",
    )


class TestAuthTokenCaching(unittest.TestCase):
    def test_servicepytan_connect_returns_mapping_compatible_connection(self):
        conn = servicepytan_connect(
            api_environment=ApiEnvironment.INTEGRATION,
            app_key="app-key",
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="client-secret",
        )

        self.assertIsInstance(conn, Mapping)
        self.assertIsInstance(conn, ServiceTitanConnection)
        self.assertNotIsInstance(conn, dict)
        self.assertEqual(conn["SERVICETITAN_TENANT_ID"], "tenant-id")
        self.assertEqual(conn.tenant_id, "tenant-id")
        self.assertEqual(dict(conn)["SERVICETITAN_APP_KEY"], "app-key")
        self.assertNotIn("_auth_token", conn)

    def test_explicit_environment_controls_routing_and_blank_timezone_defaults(self):
        config = {
            "SERVICETITAN_APP_KEY": "app-key",
            "SERVICETITAN_TENANT_ID": "tenant-id",
            "SERVICETITAN_CLIENT_ID": "client-id",
            "SERVICETITAN_CLIENT_SECRET": "client-secret",
            "SERVICETITAN_APP_ID": "app-id",
            "SERVICETITAN_TIMEZONE": "",
            "SERVICETITAN_API_ENVIRONMENT": "production",
        }

        with patch("builtins.open", mock_open(read_data="{}")), \
             patch("servicepytan.auth.json.load", return_value=config):
            conn = servicepytan_connect(
                api_environment=ApiEnvironment.INTEGRATION,
                config_file="servicepytan_config.json",
            )

        self.assertEqual(conn.api_environment, ApiEnvironment.INTEGRATION)
        self.assertEqual(
            conn.api_root,
            "https://api-integration.servicetitan.io",
        )
        self.assertEqual(
            conn["SERVICETITAN_API_ENVIRONMENT"],
            ApiEnvironment.INTEGRATION,
        )
        self.assertEqual(conn.timezone, "UTC")

    @patch("servicepytan.auth.request_auth_token")
    def test_reuses_token_until_safety_window(self, mock_request_auth_token):
        mock_request_auth_token.side_effect = [
            {"access_token": "token-one", "expires_in": 900},
            {"access_token": "token-two", "expires_in": 900},
        ]
        conn = make_connection()

        with patch("servicepytan.auth.time.monotonic") as monotonic:
            monotonic.return_value = 100
            self.assertEqual(conn.get_auth_token(), "token-one")

            # A 900-second token is considered stale 60 seconds early.
            monotonic.return_value = 939
            self.assertEqual(conn.get_auth_token(), "token-one")

            monotonic.return_value = 940
            self.assertEqual(conn.get_auth_token(), "token-two")

        self.assertEqual(mock_request_auth_token.call_count, 2)

    @patch("servicepytan.auth.request_auth_token")
    def test_concurrent_first_use_fetches_one_token(self, mock_request_auth_token):
        mock_request_auth_token.return_value = {
            "access_token": "shared-token",
            "expires_in": 900,
        }
        conn = make_connection()

        with ThreadPoolExecutor(max_workers=10) as executor:
            tokens = list(executor.map(lambda _: conn.get_auth_token(), range(20)))

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
            tokens = list(executor.map(lambda _: conn.get_auth_token(), range(20)))

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
            conn.get_auth_token()

        self.assertIsNone(conn._auth_token)
        self.assertEqual(conn.get_auth_token(), "recovered-token")

    def test_stale_401_does_not_invalidate_newer_token(self):
        conn = make_connection()
        conn._auth_token = "new-token"
        conn._auth_token_valid_until = float("inf")

        conn.invalidate_auth_token(rejected_token="old-token")

        self.assertEqual(conn._auth_token, "new-token")

    @patch("servicepytan.auth.request_auth_token")
    def test_module_functions_delegate_to_connection(self, mock_request_auth_token):
        mock_request_auth_token.return_value = {
            "access_token": "cached-token",
            "expires_in": 900,
        }
        conn = make_connection()

        self.assertEqual(get_auth_token(conn), "cached-token")
        invalidate_auth_token(conn, rejected_token="cached-token")

        self.assertIsNone(conn._auth_token)

    @patch("servicepytan.auth.request_auth_token")
    def test_module_functions_continue_to_accept_legacy_mapping(
        self, mock_request_auth_token,
    ):
        mock_request_auth_token.return_value = {
            "access_token": "legacy-token",
            "expires_in": 900,
        }
        legacy_conn = {
            "SERVICETITAN_CLIENT_ID": "client-id",
            "SERVICETITAN_CLIENT_SECRET": "client-secret",
            "auth_root": "https://auth.example.com",
        }

        self.assertEqual(get_auth_token(legacy_conn), "legacy-token")


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

    def test_http_error_logs_safe_oauth_details_and_uses_timeout(self):
        mock_response = requests.Response()
        mock_response.status_code = 400
        mock_response._content = (
            b'{"error":"invalid_client","error_description":"bad credentials",'
            b'"access_token":"TOKEN_FROM_RESPONSE"}'
        )
        mock_response.url = "https://example.com/connect/token"

        with patch(
            "servicepytan.auth.requests.post", return_value=mock_response,
        ) as mock_post, self.assertLogs(
            "servicepytan.auth", level="WARNING",
        ) as log_ctx:
            with self.assertRaises(requests.HTTPError):
                request_auth_token(
                    "https://example.com",
                    "my_client_id",
                    "SUPERSECRET",
                    retry_count=1,
                )

        full_output = "\n".join(log_ctx.output)
        self.assertIn("status_code=400", full_output)
        self.assertIn("invalid_client", full_output)
        self.assertIn("bad credentials", full_output)
        self.assertNotIn("Failed to get a response", full_output)
        self.assertNotIn("TOKEN_FROM_RESPONSE", full_output)
        self.assertNotIn("SUPERSECRET", full_output)
        mock_post.assert_called_once_with(
            "https://example.com/connect/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": "my_client_id",
                "client_secret": "SUPERSECRET",
            },
            timeout=AUTH_REQUEST_TIMEOUT_SECONDS,
        )


if __name__ == "__main__":
    unittest.main()
