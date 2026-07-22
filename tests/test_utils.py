"""Tests for servicepytan.utils authentication behavior."""

import json
import unittest
from unittest.mock import call, patch

import requests

from servicepytan.auth import ApiEnvironment, ServiceTitanConnection
from servicepytan.utils import endpoint_url, get_timezone_by_file, request_json


def make_response(status_code, body):
    response = requests.Response()
    response.status_code = status_code
    response._content = json.dumps(body).encode()
    response.url = "https://api.example.com/resource"
    return response


class TestServiceTitanConnectionUtilities(unittest.TestCase):
    def setUp(self):
        self.conn = ServiceTitanConnection(
            api_environment=ApiEnvironment.INTEGRATION,
            client_id="client-id",
            client_secret="client-secret",
            app_key="app-key",
            tenant_id="tenant-id",
            timezone="America/New_York",
        )

    def test_endpoint_url_uses_connection_properties(self):
        self.assertEqual(
            endpoint_url("jpm", "jobs", conn=self.conn),
            "https://api-integration.servicetitan.io/jpm/v2/tenant/tenant-id/jobs",
        )

    def test_timezone_uses_connection_property(self):
        self.assertEqual(
            get_timezone_by_file(self.conn),
            "America/New_York",
        )


class TestRequestJsonAuthentication(unittest.TestCase):
    @patch("servicepytan.auth.request_auth_token")
    @patch("servicepytan.utils.requests.request")
    def test_401_invalidates_cached_token_and_uses_refreshed_token(
        self, mock_request, mock_request_auth_token,
    ):
        conn = ServiceTitanConnection(
            api_environment="integration",
            client_id="client-id",
            client_secret="client-secret",
            app_key="app-key",
            tenant_id="tenant-id",
        )
        mock_request_auth_token.side_effect = [
            {"access_token": "expired-token", "expires_in": 900},
            {"access_token": "fresh-token", "expires_in": 900},
        ]
        mock_request.side_effect = [
            make_response(401, {"title": "Unauthorized"}),
            make_response(200, {"ok": True}),
        ]

        result = request_json(
            "https://api.example.com/resource", conn=conn, retry_count=1,
        )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(mock_request_auth_token.call_count, 2)
        self.assertEqual(
            [request_call.kwargs["headers"]["Authorization"]
             for request_call in mock_request.call_args_list],
            ["expired-token", "fresh-token"],
        )

    @patch("servicepytan.utils.invalidate_auth_token")
    @patch("servicepytan.utils.get_auth_headers")
    @patch("servicepytan.utils.requests.request")
    def test_401_refreshes_and_retries_once_even_with_single_attempt(
        self, mock_request, mock_get_auth_headers, mock_invalidate_auth_token,
    ):
        conn = object()
        mock_get_auth_headers.side_effect = [
            {"Authorization": "expired-token", "ST-App-Key": "app-key"},
            {"Authorization": "fresh-token", "ST-App-Key": "app-key"},
        ]
        mock_request.side_effect = [
            make_response(401, {"title": "Unauthorized"}),
            make_response(200, {"ok": True}),
        ]

        result = request_json(
            "https://api.example.com/resource", conn=conn, retry_count=1,
        )

        self.assertEqual(result, {"ok": True})
        self.assertEqual(mock_request.call_count, 2)
        mock_invalidate_auth_token.assert_called_once_with(
            conn, rejected_token="expired-token",
        )
        self.assertEqual(
            [request_call.kwargs["headers"]["Authorization"] for request_call in mock_request.call_args_list],
            ["expired-token", "fresh-token"],
        )

    @patch("servicepytan.utils.time.sleep")
    @patch("servicepytan.utils.invalidate_auth_token")
    @patch("servicepytan.utils.get_auth_headers")
    @patch("servicepytan.utils.requests.request")
    def test_second_401_is_not_retried_by_generic_retry_loop(
        self, mock_request, mock_get_auth_headers, mock_invalidate_auth_token, mock_sleep,
    ):
        conn = object()
        mock_get_auth_headers.side_effect = [
            {"Authorization": "expired-token", "ST-App-Key": "app-key"},
            {"Authorization": "rejected-token", "ST-App-Key": "app-key"},
        ]
        mock_request.side_effect = [
            make_response(401, {"title": "Unauthorized"}),
            make_response(401, {"title": "Unauthorized"}),
        ]

        with self.assertRaises(requests.HTTPError):
            request_json(
                "https://api.example.com/resource", conn=conn, retry_count=3,
            )

        self.assertEqual(mock_request.call_count, 2)
        self.assertEqual(
            mock_invalidate_auth_token.call_args_list,
            [
                call(conn, rejected_token="expired-token"),
                call(conn, rejected_token="rejected-token"),
            ],
        )
        mock_sleep.assert_not_called()

    @patch("servicepytan.utils.get_auth_headers")
    @patch("servicepytan.utils.requests.request")
    def test_authorization_header_is_redacted_from_success_log(
        self, mock_request, mock_get_auth_headers,
    ):
        mock_get_auth_headers.return_value = {
            "Authorization": "SECRET_ACCESS_TOKEN",
            "ST-App-Key": "SECRET_APP_KEY",
        }
        mock_request.return_value = make_response(200, {"ok": True})

        with self.assertLogs("servicepytan.utils", level="INFO") as log_ctx:
            request_json("https://api.example.com/resource", conn=object())

        full_output = "\n".join(log_ctx.output)
        self.assertNotIn("SECRET_ACCESS_TOKEN", full_output)
        self.assertNotIn("SECRET_APP_KEY", full_output)
        self.assertNotIn("Authorization", full_output)

    @patch("servicepytan.utils.time.sleep")
    @patch("servicepytan.utils.get_auth_headers")
    @patch("servicepytan.utils.requests.request")
    def test_authorization_header_is_redacted_from_error_log(
        self, mock_request, mock_get_auth_headers, mock_sleep,
    ):
        mock_get_auth_headers.return_value = {
            "Authorization": "SECRET_ACCESS_TOKEN",
            "ST-App-Key": "SECRET_APP_KEY",
        }
        mock_request.return_value = make_response(500, {"title": "failure"})

        with self.assertLogs("servicepytan.utils", level="WARNING") as log_ctx:
            with self.assertRaises(requests.HTTPError):
                request_json(
                    "https://api.example.com/resource", conn=object(), retry_count=1,
                )

        full_output = "\n".join(log_ctx.output)
        self.assertNotIn("SECRET_ACCESS_TOKEN", full_output)
        self.assertNotIn("SECRET_APP_KEY", full_output)
        self.assertNotIn("Authorization", full_output)
        mock_sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
