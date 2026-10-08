"""Utility Functions for Supporting Other Modules"""
import requests
import time
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from servicepytan.auth import (
  get_auth_headers,
  get_tenant_id,
  invalidate_auth_token,
)

import logging

logging.basicConfig()
logger = logging.getLogger(__name__)


DEFAULT_TIMEOUT = (5, 60)
RETRY_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "DELETE"})
_sessions = threading.local()


def _get_session(retry_count):
  sessions = getattr(_sessions, 'sessions', None)
  if sessions is None:
    sessions = _sessions.sessions = {}
  if retry_count not in sessions:
    retries = retry_count - 1
    retry = Retry(
      total=retries, connect=retries, read=retries, status=retries, other=0,
      status_forcelist=(502, 503, 504), allowed_methods=RETRY_METHODS,
      backoff_factor=0.5, raise_on_status=False, respect_retry_after_header=False,
    )
    session = requests.Session()
    for scheme in ('https://', 'http://'):
      session.mount(scheme, HTTPAdapter(max_retries=retry))
    sessions[retry_count] = session
  return sessions[retry_count]


def _response_detail(response, verbose, include_text=False):
  if not verbose:
    content_length = len(response.content) if response.content else 0
    return f"content_length={content_length} bytes"

  detail = f"content={response.content}"
  if include_text:
    detail = f"{detail}, text={response.text}"
  return detail


def request_json(url, options={}, payload={}, conn=None, request_type="GET", json_payload={}, retry_count=3, verbose=True, timeout=DEFAULT_TIMEOUT):
  """Makes the request to the API and returns JSON

  Retrieves JSON response from provided URL with a number of parameters to customize the request.

  Args:
      url: A string with the full URL request
      options: A dictionary defining the parameters to add to the url for filtering
      payload: A dictionary defining the data object to create or update
      conn: a ServiceTitanConnection or legacy credential mapping.
      request_type: A string to define the REST endpoint type [GET, POST, PUT, PATCH, DEL].
      json_payload: A dictionary defining the JSON payload to send
      retry_count: Transport attempts per send, including the initial request (at least 1).
          Also bounds 429 replays; a token refresh allows one extra send.
      timeout: Connect and read timeout in seconds; read bounds silence between bytes.
          PUT, POST and PATCH use fresh connections and only retry ConnectTimeout,
          429, or a single token refresh. GET, HEAD, OPTIONS and DELETE use thread-local sessions.

  Returns:
      JSON Object

  Raises:
      TBD
  """

  if not isinstance(retry_count, int) or retry_count < 1:
    raise ValueError("retry_count must be a positive integer")
  request_type = request_type.upper()
  if request_type == "DEL":
    request_type = "DELETE"
  safe_method = request_type in RETRY_METHODS
  send = _get_session(retry_count).request if safe_method else requests.request
  headers = get_auth_headers(conn)
  auth_retry_attempted = False
  attempt = 0
  while attempt < retry_count:
    response = None
    request_error = None
    try:
      response = send(request_type, url, data=payload, headers=headers, params=options, json=json_payload, timeout=timeout, allow_redirects=safe_method)
    except requests.RequestException as error:
      request_error = error
    else:
      response_detail = _response_detail(
        response, verbose, include_text=True,
      )
      if verbose:
        logger.info(f"Response: request_url={url}, payload={payload}, json_payload={json_payload} =>  status_code={response.status_code}, {response_detail}")
      else:
        logger.info(f"Response: request_url={url} => status_code={response.status_code}, {response_detail}")

      # A 401 response means ServiceTitan rejected the request before applying
      # it, so refreshing the token and replaying once is safe for every method,
      # including non-idempotent POST/PUT calls.
      if response.status_code == requests.codes.unauthorized:
        if not auth_retry_attempted:
          logger.warning(
            f"ServiceTitan request was unauthorized; refreshing the token "
            f"and replaying once (url={url}, request_type={request_type}, "
            f"status_code={response.status_code})."
          )
          rejected_token = headers.get('Authorization')
          invalidate_auth_token(conn, rejected_token=rejected_token)
          auth_retry_attempted = True
          # OAuth refresh failures must propagate with their own response and
          # must not be rewritten as the stale API 401 response.
          headers = get_auth_headers(conn)
          continue
        # A fresh token was already tried. Retain it because this 401 may come
        # from the app key, tenant, or scopes rather than token expiration.
        response_detail = _response_detail(response, verbose)
        logger.warning(
          f"ServiceTitan request remained unauthorized after one token "
          f"refresh (url={url}, request_type={request_type}, "
          f"status_code={response.status_code}, {response_detail})."
        )
        response.raise_for_status()

      try:
        # Redirects can replay a write whose outcome we cannot verify.
        if not safe_method and 300 <= response.status_code < 400:
          raise requests.HTTPError("Unexpected redirect for ServiceTitan write", response=response)
        if response.status_code != requests.codes.ok:
          response.raise_for_status()

        # This may not always be JSON.
        try:
          return response.json()
        except ValueError:
          return response.content
      except Exception as error:
        request_error = error

    attempt += 1
    if response is None:
      error_log = f"Error fetching data (url={url}, payload={payload}, RETRY=({attempt} / {retry_count})): Failed to get a response. error: {request_error}"
    elif verbose:
      response_detail = _response_detail(
        response, verbose, include_text=True,
      )
      error_log = f"Error fetching data (url={url}, payload={payload}, RETRY=({attempt} / {retry_count})): {response_detail}, error: {request_error}"
    else:
      response_detail = _response_detail(response, verbose)
      error_log = f"Error fetching data (url={url}, RETRY=({attempt} / {retry_count})): {response_detail}, error: {request_error}"

    logger.warning(error_log)
    # The adapter owns retries for safe methods. A write may have reached ST
    # even when its response was lost; only a connect timeout proves it did not.
    rate_limited = response is not None and response.status_code == 429
    connect_timeout = not safe_method and isinstance(request_error, requests.ConnectTimeout)
    if attempt < retry_count and (rate_limited or connect_timeout):
      delay = 0.5 * (2 ** (attempt - 1))
      if rate_limited:
        delay = Retry().get_retry_after(response) or delay
      time.sleep(delay)
      continue

    if getattr(request_error, "response", None) is None:
      request_error.response = response
    raise request_error

def check_default_options(options):
  """Add sensible defaults to options when not defined"""
  # TODO: Add ability to read from a configuration file
  if "pageSize" not in options:
    options["pageSize"] = 100
  
  return options

def endpoint_url(folder, endpoint, id="", modifier="", conn=None, tenant_id=""):
  """Constructs API request URL based on key parameters

  Retrives JSON response from provided URL with a number of parameters to customize the request.

  Args:
      folder: A string based on the endpoint groupings
      endpoint: A string indicating the endpoint you want to address.
      id: A string for the id of the endpoint object you're addressing.
      modifier: A string to modify the url to address the additional endpoint.
      conn: a ServiceTitanConnection or legacy credential mapping.
      tenant_id: A string to manually adjust the tenant id.

  Returns:
      A URL String

  Raises:
      TBD
  """  
  # Adds ability to manually switch up the Tenant ID for apps that have multiples
  if tenant_id == "":
    tenant_id = get_tenant_id(conn)

  api_root = conn['api_root']
  url = f"{api_root}/{folder}/v2/tenant/{tenant_id}/{endpoint}"
  if id != "": url = f"{url}/{id}"
  if modifier != "": url = f"{url}/{modifier}"
  return url
    
def create_credential_file(name="servicepytan_config.json"):
  """Creates and saves an unfilled configuration file.

  Args:
      name: a dictionary containing the credential config

  Returns:
      A filepath string
  """  
  file = open(name, 'w')
  file.write(
    """{
    "SERVICETITAN_CLIENT_ID": "",
    "SERVICETITAN_CLIENT_SECRET": "",
    "SERVICETITAN_APP_ID": "",
    "SERVICETITAN_APP_KEY": "",
    "SERVICETITAN_TENANT_ID": ""
    }"""
  )
  file.close()
  return name

def get_timezone_by_file(conn=None):
  """Retrieves timezone from the configuration file.

  Args:
      conn: a ServiceTitanConnection or legacy credential mapping.

  Returns:
      Timezone string
  """    
  return conn.get("SERVICETITAN_TIMEZONE") or "UTC"

def sleep_with_countdown(sleep_time):
  """Sleeps for a given amount of time with a countdown"""
  for i in range(sleep_time, 0, -1):
      logger.info("Trying again in {} seconds...       ".format(i),end='\r')
      time.sleep(1)
  logger.info("")
  pass

def request_json_with_retry(url, options={}, payload="", conn=None, request_type="GET", json_payload="", verbose=True, timeout=DEFAULT_TIMEOUT):
  """Makes the request to the API and returns JSON with a retry

  Retrieves JSON response from provided URL with a number of parameters to customize the request.

  Args:
      url: A string with the full URL request
      options: A dictionary defining the parameters to add to the url for filtering
      payload: A dictionary defining the data object to create or update
      conn: a ServiceTitanConnection or legacy credential mapping.
      request_type: A string to define the REST endpoint type [GET, POST, PUT, PATCH, DEL].
      retry_count: An integer for the number of times to retry the request.
      sleep_time: An integer for the number of seconds to sleep between retries.

  Returns:
      JSON Object

  Raises:
      TBD
  """
  return request_json(url, options=options, payload=payload, conn=conn,
                      request_type=request_type, json_payload=json_payload,
                      verbose=verbose, timeout=timeout)
