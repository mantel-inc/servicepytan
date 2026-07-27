"""Utility Functions for Supporting Other Modules"""
import requests
import time
from servicepytan.auth import (
  get_auth_headers,
  get_tenant_id,
  invalidate_auth_token,
)

import logging

logging.basicConfig()
logger = logging.getLogger(__name__)

def request_json(url, options={}, payload={}, conn=None, request_type="GET", json_payload={}, retry_count=3, verbose=True):
  """Makes the request to the API and returns JSON

  Retrieves JSON response from provided URL with a number of parameters to customize the request.

  Args:
      url: A string with the full URL request
      options: A dictionary defining the parameters to add to the url for filtering
      payload: A dictionary defining the data object to create or update
      conn: a ServiceTitanConnection or legacy credential mapping.
      request_type: A string to define the REST endpoint type [GET, POST, PUT, PATCH, DEL].
      json_payload: A dictionary defining the JSON payload to send
      retry_count: An integer for the number of times to retry the request.

  Returns:
      JSON Object

  Raises:
      TBD
  """

  headers = get_auth_headers(conn)
  auth_retry_attempted = False
  attempt = 0
  while attempt < retry_count:
    response = None
    request_error = None
    try:
      response = requests.request(request_type, url, data=payload, headers=headers, params=options, json=json_payload)
    except Exception as error:
      request_error = error
    else:
      if verbose:
        logger.info(f"Response: request_url={url}, payload={payload}, json_payload={json_payload} =>  status_code={response.status_code}, content={response.content}, text={response.text}")
      else:
        content_length = len(response.content) if response.content else 0
        logger.info(f"Response: request_url={url} => status_code={response.status_code}, content_length={content_length} bytes")

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
        if verbose:
          response_detail = f"content={response.content}"
        else:
          content_length = len(response.content) if response.content else 0
          response_detail = f"content_length={content_length} bytes"
        logger.warning(
          f"ServiceTitan request remained unauthorized after one token "
          f"refresh (url={url}, request_type={request_type}, "
          f"status_code={response.status_code}, {response_detail})."
        )
        response.raise_for_status()

      try:
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
      error_log = f"Error fetching data (url={url}, payload={payload}, RETRY=({attempt} / {retry_count})): content: {response.content}, text: {response.text}, error: {request_error}"
    else:
      content_length = len(response.content) if response.content else 0
      error_log = f"Error fetching data (url={url}, RETRY=({attempt} / {retry_count})): content_length: {content_length} bytes, error: {request_error}"

    logger.warning(error_log)
    if attempt < retry_count:
      time.sleep(1)
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

def request_json_with_retry(url, options={}, payload="", conn=None, request_type="GET", json_payload="", verbose=True):
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
  response = request_json(url, options=options, payload=payload, conn=conn, request_type=request_type, json_payload=json_payload, verbose=verbose)
  if "traceId" in response:
    if response['status'] == 429:
        sleep_time = response['title'].split(" ")[-2]
        logger.warning("Rate Limit Exceeded. Retrying in {} seconds...".format(sleep_time))
        sleep_with_countdown(int(sleep_time))
        response = request_json_with_retry(url, options=options, payload=payload, conn=conn, request_type=request_type, json_payload=json_payload, verbose=verbose)
  
  return response
