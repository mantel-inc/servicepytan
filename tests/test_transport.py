import unittest
from unittest.mock import patch

import requests

from servicepytan.utils import request_json
from tests.test_utils import make_response


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.auth = patch('servicepytan.utils.get_auth_headers', return_value={})
        self.auth.start()
        self.addCleanup(self.auth.stop)

    @patch('servicepytan.utils.requests.request')
    def test_write_has_default_timeout(self, send):
        send.return_value = make_response(200, {'ok': True})
        self.assertEqual(request_json('https://example.com', request_type='POST'), {'ok': True})
        self.assertEqual(send.call_args.kwargs['timeout'], (5, 60))

    @patch('servicepytan.utils.requests.request')
    def test_timeout_override(self, send):
        send.return_value = make_response(200, {})
        request_json('https://example.com', request_type='POST', timeout=(2, 120))
        self.assertEqual(send.call_args.kwargs['timeout'], (2, 120))

    @patch('servicepytan.utils.time.sleep')
    @patch('servicepytan.utils.requests.request')
    def test_ambiguous_writes_are_never_replayed(self, send, sleep):
        for method in ('POST', 'PATCH', 'PUT'):
            for error in (requests.ReadTimeout('silent'), requests.ConnectionError('reset')):
                with self.subTest(method=method, error=error):
                    send.reset_mock()
                    send.side_effect = error
                    with self.assertRaises(type(error)):
                        request_json('https://example.com', request_type=method)
                    self.assertEqual(send.call_count, 1)
            for status in (400, 404, 500, 502, 503, 504):
                with self.subTest(method=method, status=status):
                    send.reset_mock()
                    send.side_effect = None
                    response = make_response(status, {})
                    send.return_value = response
                    with self.assertRaises(requests.HTTPError) as caught:
                        request_json('https://example.com', request_type=method)
                    self.assertIs(caught.exception.response, response)
                    self.assertEqual(send.call_count, 1)
        sleep.assert_not_called()

    @patch('servicepytan.utils.time.sleep')
    @patch('servicepytan.utils.requests.request')
    def test_write_connect_timeout_can_retry(self, send, sleep):
        send.side_effect = [requests.ConnectTimeout(), make_response(200, {'ok': True})]
        self.assertEqual(request_json('https://example.com', request_type='POST'), {'ok': True})
        self.assertEqual(send.call_count, 2)

    @patch('servicepytan.utils.time.sleep')
    @patch('servicepytan.utils.requests.request')
    def test_rate_limit_replay_is_bounded_and_respects_header(self, send, sleep):
        response = make_response(429, {})
        response.headers['Retry-After'] = '2'
        send.return_value = response
        with self.assertRaises(requests.HTTPError):
            request_json('https://example.com', request_type='POST', retry_count=3)
        self.assertEqual(send.call_count, 3)
        self.assertEqual([c.args for c in sleep.call_args_list], [(2,), (2,)])


class SessionTransportTests(unittest.TestCase):
    def setUp(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        self.statuses = [200]
        self.calls = 0
        self.delay = 0
        test = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                import time
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                test.calls += 1
                status = test.statuses[min(test.calls - 1, len(test.statuses) - 1)]
                time.sleep(test.delay)
                self.send_response(status)
                if status == 307:
                    self.send_header("Location", "/other")
                self.send_header("Content-Length", "12")
                self.end_headers()
                try:
                    self.wfile.write(b'{"ok": true}')
                except (BrokenPipeError, ConnectionResetError):
                    pass

            do_DELETE = do_GET
            do_POST = do_GET

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=self.server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = 'http://127.0.0.1:{}/'.format(self.server.server_port)
        auth = patch('servicepytan.utils.get_auth_headers', return_value={})
        auth.start()
        self.addCleanup(auth.stop)

    def test_write_redirect_does_not_reach_second_url(self):
        self.statuses = [307, 200]
        with self.assertRaises(requests.HTTPError) as caught:
            request_json(self.url, request_type='POST')
        self.assertEqual(caught.exception.response.status_code, 307)
        self.assertEqual(self.calls, 1)

    def test_safe_methods_retry_transient_status(self):
        for method in ('GET', 'DELETE'):
            with self.subTest(method=method):
                self.calls = 0
                self.statuses = [503, 200]
                self.assertEqual(request_json(self.url, request_type=method), {'ok': True})
                self.assertEqual(self.calls, 2)

    def test_retry_count_means_total_attempts_and_preserves_response(self):
        self.statuses = [503]
        with self.assertRaises(requests.HTTPError) as caught:
            request_json(self.url, retry_count=2)
        self.assertEqual(self.calls, 2)
        self.assertEqual(caught.exception.response.status_code, 503)

    def test_single_attempt_disables_adapter_retries(self):
        self.statuses = [503, 200]
        with self.assertRaises(requests.HTTPError):
            request_json(self.url, retry_count=1)
        self.assertEqual(self.calls, 1)

    def test_not_found_is_not_retried(self):
        self.statuses = [404, 200]
        with self.assertRaises(requests.HTTPError) as caught:
            request_json(self.url)
        self.assertEqual(self.calls, 1)
        self.assertEqual(caught.exception.response.status_code, 404)

    def test_silent_server_times_out(self):
        self.delay = 0.2
        with self.assertRaises(requests.RequestException):
            request_json(self.url, timeout=(0.05, 0.05), retry_count=2)
        self.assertEqual(self.calls, 2)

    def test_sessions_are_reused_only_within_same_thread_and_budget(self):
        import threading
        from servicepytan.utils import _get_session
        session = _get_session(3)
        self.assertIs(session, _get_session(3))
        self.assertIsNot(session, _get_session(1))
        other = []
        worker = threading.Thread(target=lambda: other.append(_get_session(3)))
        worker.start()
        worker.join()
        self.assertIsNot(session, other[0])
        other[0].close()


class EndpointTimeoutTests(unittest.TestCase):
    @patch('servicepytan.requests.endpoint_url', return_value='https://example.com')
    @patch('servicepytan.requests.request_json', return_value={'data': [], 'hasMore': False})
    def test_endpoint_methods_forward_timeout(self, send, url):
        from servicepytan.requests import Endpoint
        endpoint = Endpoint('crm', 'customers')
        calls = [
            lambda: endpoint.get_one(1, timeout=(5, 120)),
            lambda: endpoint.get_many(timeout=(5, 120)),
            lambda: endpoint.get_all(timeout=(5, 120)),
            lambda: endpoint.create({}, timeout=(5, 120)),
            lambda: endpoint.update(1, {}, timeout=(5, 120)),
            lambda: endpoint.delete(1, timeout=(5, 120)),
            lambda: endpoint.delete_subitem(1, 2, 'notes', timeout=(5, 120)),
            lambda: endpoint.export_one('customers', timeout=(5, 120)),
            lambda: endpoint.export_all('customers', timeout=(5, 120)),
        ]
        for invoke in calls:
            invoke()
            self.assertEqual(send.call_args.kwargs['timeout'], (5, 120))


class RedirectTests(unittest.TestCase):
    @patch('servicepytan.utils.get_auth_headers', return_value={})
    @patch('servicepytan.utils.requests.request')
    def test_write_redirects_are_rejected(self, send, auth):
        for method in ('POST', 'PATCH', 'PUT'):
            for status in (301, 302, 303, 307, 308):
                with self.subTest(method=method, status=status):
                    send.reset_mock()
                    response = make_response(status, {})
                    response.headers['Location'] = '/other'
                    send.return_value = response
                    with self.assertRaises(requests.HTTPError) as caught:
                        request_json('https://example.com', request_type=method)
                    self.assertIs(caught.exception.response, response)
                    self.assertEqual(send.call_count, 1)
                    self.assertFalse(send.call_args.kwargs['allow_redirects'])


class ReportTimeoutTests(unittest.TestCase):
    @patch('servicepytan.reports.endpoint_url', return_value='https://example.com')
    @patch('servicepytan.reports.request_json_with_retry')
    def test_report_timeout_reaches_metadata_and_every_page(self, send, url):
        from servicepytan.reports import Report
        send.side_effect = [
            {},
            {'data': [1], 'fields': [], 'totalCount': 2, 'hasMore': True},
            {'data': [2], 'fields': [], 'totalCount': 2, 'hasMore': False},
        ]
        report = Report('category', 'id', timeout=(5, 120))
        report.get_all_data(timeout=(5, 180))
        self.assertEqual([c.kwargs['timeout'] for c in send.call_args_list],
                         [(5, 120), (5, 180), (5, 180)])

    @patch('servicepytan.reports.endpoint_url', return_value='https://example.com')
    @patch('servicepytan.reports.request_json_with_retry', return_value={})
    def test_report_retains_configured_timeout(self, send, url):
        from servicepytan.reports import Report
        report = Report('category', 'id', timeout=(5, 120))
        report.get_data()
        self.assertEqual(send.call_args.kwargs['timeout'], (5, 120))
