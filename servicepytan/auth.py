"""Authenticating with ServiceTitan API"""

import time
import threading
import requests
import json
import os
from collections.abc import Mapping
from concurrent.futures import Future
from dotenv import dotenv_values, load_dotenv
from enum import StrEnum

import logging

logging.basicConfig()
logger = logging.getLogger(__name__)


class ApiEnvironment(StrEnum):
    PRODUCTION  = "production",
    INTEGRATION = "integration"

def get_auth_root_url(env: str) -> str:
    match env:
        case ApiEnvironment.PRODUCTION:
            return "https://auth.servicetitan.io"
        case ApiEnvironment.INTEGRATION:
            return "https://auth-integration.servicetitan.io"
        case _:
            raise ValueError(f"Unknown ApiEnvironment: {env}")

def get_api_root_url(env: str) -> str:
    match env:
        case ApiEnvironment.PRODUCTION:
            return "https://api.servicetitan.io"
        case ApiEnvironment.INTEGRATION:
            return "https://api-integration.servicetitan.io"
        case _:
            raise ValueError(f"Unknown ApiEnvironment: {env}")


CREDENTIAL_VARIABLES = [
    'SERVICETITAN_APP_KEY',
    'SERVICETITAN_TENANT_ID',
    'SERVICETITAN_CLIENT_ID',
    'SERVICETITAN_CLIENT_SECRET',
    'SERVICETITAN_APP_ID',
]

ROUTING_VARIABLES = [
    'SERVICETITAN_TIMEZONE',
    'SERVICETITAN_API_ENVIRONMENT',
]

AUTH_VARIABLES = CREDENTIAL_VARIABLES + ROUTING_VARIABLES

TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS = 60
AUTH_REQUEST_TIMEOUT_SECONDS = 30


class ServiceTitanConnection(Mapping):
  """Read-only configuration mapping and process-local OAuth lifecycle.

  Connection instances contain a thread lock and should not be serialized,
  copied, or shared across processes.
  """

  _KEY_TO_ATTRIBUTE = {
      "SERVICETITAN_APP_KEY": "app_key",
      "SERVICETITAN_TENANT_ID": "tenant_id",
      "SERVICETITAN_CLIENT_ID": "client_id",
      "SERVICETITAN_CLIENT_SECRET": "client_secret",
      "SERVICETITAN_APP_ID": "app_id",
      "SERVICETITAN_TIMEZONE": "timezone",
      "SERVICETITAN_API_ENVIRONMENT": "api_environment",
      "auth_root": "auth_root",
      "api_root": "api_root",
  }

  def __init__(self, api_environment, app_key, tenant_id, client_id,
               client_secret, app_id=None, timezone="UTC"):
    self.api_environment = api_environment
    self.app_key = app_key
    self.tenant_id = tenant_id
    self.client_id = client_id
    self.client_secret = client_secret
    self.app_id = app_id
    self.timezone = timezone
    self.auth_root = get_auth_root_url(api_environment)
    self.api_root = get_api_root_url(api_environment)

    self._auth_token = None
    self._auth_token_valid_until = 0.0
    self._auth_token_lock = threading.Lock()
    self._auth_token_refresh = None

  def __getitem__(self, key):
    return getattr(self, self._KEY_TO_ATTRIBUTE[key])

  def __iter__(self):
    return iter(self._KEY_TO_ATTRIBUTE)

  def __len__(self):
    return len(self._KEY_TO_ATTRIBUTE)

  def _get_cached_auth_token(self):
    if (self._auth_token is not None and
        time.monotonic() < self._auth_token_valid_until):
      return self._auth_token
    return None

  def _cache_auth_token(self, token_response):
    token = token_response['access_token']
    try:
      expires_in = max(0.0, float(token_response.get('expires_in', 0)))
    except (TypeError, ValueError):
      expires_in = 0.0

    # Use a full minute for normal ServiceTitan tokens (currently 15 minutes),
    # but keep a proportional margin for unusually short-lived tokens.
    safety_margin = min(
        TOKEN_EXPIRY_SAFETY_MARGIN_SECONDS, expires_in * 0.1,
    )
    self._auth_token = token
    self._auth_token_valid_until = (
        time.monotonic() + max(0.0, expires_in - safety_margin)
    )
    return token

  def get_auth_token(self):
    """Return a cached OAuth token, refreshing near expiration."""
    refresh = None
    owns_refresh = False
    try:
      with self._auth_token_lock:
        cached_token = self._get_cached_auth_token()
        if cached_token is not None:
          return cached_token

        refresh = self._auth_token_refresh
        if refresh is None:
          refresh = Future()
          owns_refresh = True
          self._auth_token_refresh = refresh

      if not owns_refresh:
        return refresh.result()

      token_response = request_auth_token(
          self.auth_root, self.client_id, self.client_secret,
      )
      with self._auth_token_lock:
        token = self._cache_auth_token(token_response)
        refresh.set_result(token)
        if self._auth_token_refresh is refresh:
          self._auth_token_refresh = None
      return token
    except BaseException as error:
      if owns_refresh:
        with self._auth_token_lock:
          if not refresh.done():
            refresh.set_exception(error)
          if self._auth_token_refresh is refresh:
            self._auth_token_refresh = None
      raise

  def invalidate_auth_token(self, rejected_token=None):
    """Invalidate a token without discarding a newer concurrent refresh."""
    with self._auth_token_lock:
      if rejected_token is None or self._auth_token == rejected_token:
        self._auth_token = None
        self._auth_token_valid_until = 0.0

  def get_auth_headers(self):
    """Return authorization headers for a ServiceTitan API request."""
    return {
        "Authorization": self.get_auth_token(),
        "ST-App-Key": self.app_key,
    }


def _read_configured_routing(source, fallback=None):
    fallback = fallback or {}
    return {
        key: source.get(key, fallback.get(key))
        for key in ROUTING_VARIABLES
    }


def _resolve_configured_value(
    name, requested, configured, default, configured_source,
):
    if requested is not None:
        if configured and configured != requested:
            logger.warning(
                "Ignoring configured %s=%r; the explicit argument %r wins.",
                name,
                configured,
                requested,
            )
        return requested, "explicit argument"

    if configured:
        logger.info(
            "Using configured %s=%r from %s.",
            name,
            configured,
            configured_source,
        )
        return configured, configured_source

    return default, "default"


def _validate_api_environment(value, source):
    try:
        return ApiEnvironment(value)
    except (TypeError, ValueError):
        expected = ", ".join(environment.value for environment in ApiEnvironment)
        raise ValueError(
            "Invalid SERVICETITAN_API_ENVIRONMENT value "
            f"{value!r} from {source}; expected one of: {expected}."
        ) from None


def _normalize_api_environment(value, source):
    if isinstance(value, str):
        value = value.strip().lower()
        if not value:
            _validate_api_environment(value, source)
    return value


def servicepytan_connect(
    api_environment: str=None,
    app_key:str=None, tenant_id:str=None, client_id:str=None, 
    client_secret:str=None, app_id:str=None, timezone:str=None, config_file:str=None):
    requested_environment = _normalize_api_environment(
        api_environment,
        "explicit argument",
    )
    requested_timezone = timezone
    configured_routing = {}
    configured_source = "configuration"
    
    auth_config = {
        "SERVICETITAN_APP_KEY": app_key,
        "SERVICETITAN_TENANT_ID": tenant_id,
        "SERVICETITAN_CLIENT_ID": client_id,
        "SERVICETITAN_CLIENT_SECRET": client_secret,
        "SERVICETITAN_APP_ID": app_id,
    }


    # First check if the config_file is provided
    if config_file:
        logger.info("Setting auth config from file...")
        with open(config_file) as config:
            creds = json.load(config)
        configured_routing = _read_configured_routing(creds)
        configured_source = f"config file {config_file!r}"
        for var in CREDENTIAL_VARIABLES:
            auth_config[var] = creds.get(var, '')

    # If not, check if the environment variables are set
    # AFAICT, app_id is never used in the rest of the code, so it isn't necessary
    elif not app_key or not tenant_id or not client_id or not client_secret:
        load_dotenv()
        logger.info("Auth config not provided, loading from environment variables...")
        for var in CREDENTIAL_VARIABLES:
            auth_var = os.environ.get(var)
            if auth_var:
                auth_config[var] = auth_var
            else:
                logger.info(f"Environment variable {var} not found or provided in function. Defaulting to empty string.")
                auth_config[var] = ''
        configured_routing = _read_configured_routing(os.environ)
        configured_source = "environment or .env"
    elif api_environment is None or timezone is None:
        configured_routing = _read_configured_routing(
            os.environ,
            fallback=dotenv_values(),
        )
        configured_source = "environment or .env"

    raw_configured_environment = configured_routing.get(
        'SERVICETITAN_API_ENVIRONMENT',
    )
    configured_environment = _normalize_api_environment(
        raw_configured_environment,
        configured_source,
    )
    resolved_environment, environment_source = _resolve_configured_value(
        'SERVICETITAN_API_ENVIRONMENT',
        requested_environment,
        configured_environment,
        ApiEnvironment.PRODUCTION,
        configured_source,
    )
    resolved_environment = _validate_api_environment(
        resolved_environment,
        environment_source,
    )
    resolved_timezone, _ = _resolve_configured_value(
        'SERVICETITAN_TIMEZONE',
        requested_timezone,
        configured_routing.get('SERVICETITAN_TIMEZONE'),
        "UTC",
        configured_source,
    )

    # Explicit routing values win; configuration fills omitted values before
    # the production and UTC defaults are applied.
    return ServiceTitanConnection(
        api_environment=resolved_environment,
        app_key=auth_config['SERVICETITAN_APP_KEY'],
        tenant_id=auth_config['SERVICETITAN_TENANT_ID'],
        client_id=auth_config['SERVICETITAN_CLIENT_ID'],
        client_secret=auth_config['SERVICETITAN_CLIENT_SECRET'],
        app_id=auth_config['SERVICETITAN_APP_ID'],
        timezone=resolved_timezone,
    )


def _get_oauth_error_details(response):
  """Return safe OAuth error fields without logging tokens or credentials."""
  if response is None or response.status_code < 400:
    return None

  try:
    response_data = response.json()
  except (TypeError, ValueError):
    return None

  if not isinstance(response_data, dict):
    return None

  return {
      key: response_data[key]
      for key in ("error", "error_description")
      if key in response_data
  } or None

def request_auth_token(auth_root_url: str, client_id, client_secret, retry_count=3):
  """Fetches Auth Token.

  Retrieves authentication token for completing a request against the API

  Args:
      client_id: String, provided from the integration settings
      client_secret: String, provided from the integration settings
      retry_count: Number of times to retry the request

  Returns:
      Authentication token

  Raises:
      TBD
  """

  url: str = f"{auth_root_url}/connect/token"

  headers: dict = {
    "Content-Type": "application/x-www-form-urlencoded",
  }
  data: dict = {
    "grant_type": "client_credentials",
    "client_id": client_id,
    "client_secret": client_secret,
  }

  for i in range(retry_count):
    response = None
    try:
      response = requests.post(
          url,
          headers=headers,
          data=data,
          timeout=AUTH_REQUEST_TIMEOUT_SECONDS,
      )
      if response.status_code != requests.codes.ok:
        response.raise_for_status()

      return response.json()
    except Exception as e:
      safe_data = {k: ("********" if k == "client_secret" else v) for k, v in data.items()}
      if response is not None:
        oauth_error = _get_oauth_error_details(response)
        oauth_error_log = f", oauth_error={oauth_error}" if oauth_error else ""
        error_log = f"Error fetching auth token (url={url}, header={headers}, data={safe_data}, RETRY=({i + 1} / {retry_count})): status_code={response.status_code}{oauth_error_log}, error: {e}"
      else:
        error_log = f"Error fetching auth token (url={url}, header={headers}, data={safe_data}, RETRY=({i + 1} / {retry_count})): Failed to get a response. error: {e}"

      logger.warning(error_log)
      if i < retry_count - 1:
        time.sleep(1)
        continue
      else:
        raise e

def invalidate_auth_token(conn, rejected_token=None):
  """Compatibility wrapper for invalidating a connection's cached token."""
  if isinstance(conn, ServiceTitanConnection):
    conn.invalidate_auth_token(rejected_token=rejected_token)


def get_auth_token(conn):
  """Compatibility wrapper for returning a connection's OAuth token."""
  if isinstance(conn, ServiceTitanConnection):
    return conn.get_auth_token()

  # Plain dictionaries retain the legacy fetch-per-call behavior.
  client_id = conn['SERVICETITAN_CLIENT_ID']
  client_secret = conn['SERVICETITAN_CLIENT_SECRET']
  return request_auth_token(
      conn["auth_root"], client_id, client_secret,
  )["access_token"]

def get_app_key(conn):
  """Fetches App Key from the config_file.

  Retrives the APP_KEY entry from config_file.

  Args:
      config_file: String, path to the config file defaults to 'servicepytan_config.json'

  Returns:
      App Key

  Raises:
      TBD
  """
  if isinstance(conn, ServiceTitanConnection):
    return conn.app_key
  return conn['SERVICETITAN_APP_KEY']

def get_tenant_id(conn):
  """Fetches Tenant ID from the config_file.

  Retrives the TENANT_ID entry from config_file.

  Args:
      config_file: String, path to the config file defaults to 'servicepytan_config.json'

  Returns:
      Tenant ID

  Raises:
      TBD
  """
  if isinstance(conn, ServiceTitanConnection):
    return conn.tenant_id
  return conn['SERVICETITAN_TENANT_ID']

def get_auth_headers(conn):
  """Generates the Authentication Headers for each API request

  Creates an object that includes the auth token and app key formatted to create the auth headers.

  Args:
      config_file: String, path to the config file defaults to 'servicepytan_config.json'

  Returns:
      Object

  Raises:
      TBD
  """
  if isinstance(conn, ServiceTitanConnection):
    return conn.get_auth_headers()
  return {
      "Authorization": get_auth_token(conn),
      "ST-App-Key": get_app_key(conn),
  }
