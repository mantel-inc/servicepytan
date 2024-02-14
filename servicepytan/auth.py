"""Authenticating with ServiceTitan API"""

import requests
import json
import os
from dotenv import load_dotenv
from enum import StrEnum

class ApiEnvironment(StrEnum):
    PRODUCTION  = "production",
    INTEGRATION = "integration"

def get_auth_root_url(env: str) -> str:
    if env == ApiEnvironment.PRODUCTION:
        return "https://auth.servicetitan.io"
    else:
        return "https://auth-integration.servicetitan.io"

def get_api_root_url(env: str) -> str:
    if env == ApiEnvironment.PRODUCTION:
        return "https://api.servicetitan.io"
    else:
        return "https://api-integration.servicetitan.io"


AUTH_VARIABLES = [
    'SERVICETITAN_APP_KEY',
    'SERVICETITAN_TENANT_ID',
    'SERVICETITAN_CLIENT_ID',
    'SERVICETITAN_CLIENT_SECRET',
    'SERVICETITAN_APP_ID',
    'SERVICETITAN_TIMEZONE',

    'SERVICETITAN_API_ENVIRONMENT'  # Optional. One of values of the ApiEnvironemnt enum.
]

def servicepytan_connect(
    api_environment: str,
    app_key:str=None, tenant_id:str=None, client_id:str=None, 
    client_secret:str=None, app_id:str=None, timezone:str="UTC", config_file:str=None):
    
    auth_config_object = {
            "SERVICETITAN_APP_KEY": app_key,
            "SERVICETITAN_TENANT_ID": tenant_id,
            "SERVICETITAN_CLIENT_ID": client_id,
            "SERVICETITAN_CLIENT_SECRET": client_secret,
            "SERVICETITAN_APP_ID": app_id,
            "SERVICETITAN_TIMEZONE": timezone,

            'SERVICETITAN_API_ENVIRONMENT': api_environment,

            "auth_root": get_auth_root_url(api_environment),
            "api_root": get_api_root_url(api_environment),
    }


    # First check if the config_file is provided
    if config_file:
        print("Setting auth config from file...")
        f = open(config_file)
        creds = json.load(f)
        for var in AUTH_VARIABLES:
            auth_config_object[var] = creds.get(var, '')
        f.close()

    # If not, check if the environment variables are set
    # AFAICT, app_id is never used in the rest of the code, so it isn't necessary
    elif not api_environment or not app_key or not tenant_id or not client_id or not client_secret:
        load_dotenv()
        print("Auth config not provided, loading from environment variables...")
        for var in AUTH_VARIABLES:
            auth_var = os.environ.get(var)
            if auth_var:
                auth_config_object[var] = auth_var
            else:
                print(f"Environment variable {var} not found or provided in function. Defualting to empty string.")
                auth_config_object[var] = ''

    return auth_config_object

def request_auth_token(auth_root_url: str, client_id, client_secret):
  """Fetches Auth Token.

  Retrieves authentication token for completing a request against the API

  Args:
      client_id: String, provided from the integration settings
      client_secret: String, provided from the integration settings

  Returns:
      Authentication token

  Raises:
      TBD
  """

  url = f"{auth_root_url}/connect/token"

  querystring = {"Content-Type":"application/x-www-form-urlencoded"}

  payload = f"grant_type=client_credentials&client_id={client_id}&client_secret={client_secret}"
  headers = {"Content-Type": "application/x-www-form-urlencoded"}

  response = requests.request("POST", url, data=payload, headers=headers, params=querystring)
  if response.status_code != requests.codes.ok:
    print(f"Error fetching auth token: {response.text}")
    response.raise_for_status()

  return json.loads(response.text)

def get_auth_token(conn):
  """Fetches Auth Token using the config_file.

  Retrives the CLIENT_ID and CLIENT_SECRET entries from config_file.

  Args:
      config_file: String, path to the config file defaults to 'servicepytan_config.json'

  Returns:
      Authentication token

  Raises:
      TBD
  """
  # Read File
  client_id = conn['SERVICETITAN_CLIENT_ID']
  client_secret = conn['SERVICETITAN_CLIENT_SECRET']
  return request_auth_token(conn["auth_root"], client_id, client_secret)["access_token"]

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
  app_key = conn['SERVICETITAN_APP_KEY']
  return app_key

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
  tenant_id = conn['SERVICETITAN_TENANT_ID']
  return tenant_id 

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
  return {
      "Authorization": get_auth_token(conn),
      "ST-App-Key": get_app_key(conn)
  }