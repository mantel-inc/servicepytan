=======
History
=======

Unreleased
----------

* Cache OAuth access tokens for their advertised lifetime and share both successful and failed refresh outcomes across concurrent callers.
* Retry an HTTP 401 once with a fresh token and redact authorization values from request logs.
* ``servicepytan_connect`` now returns a read-only ``Mapping`` with process-local token state; do not mutate, serialize, copy, or share the connection across processes.
* A second HTTP 401 after the fresh-token replay is raised immediately instead of entering the generic request retry loop.
* ``get_auth_token`` may return a cached token until its safety window begins (up to 60 seconds before its advertised expiration).
* Explicit environment and timezone arguments take precedence over config-file or environment values; omitted arguments use configured values before production and UTC defaults.
* Configured ``SERVICETITAN_API_ENVIRONMENT`` values now control routing when the explicit argument is omitted. Existing config files and environment variables should be checked during upgrade; values are normalized for case and surrounding whitespace, then validated before use.
* Authentication credentials are not merged across sources: config-file values replace explicit credential arguments, while omitting any required argument without a config file loads every credential from the environment.

0.1.0 (2022-03-27)
------------------

* First release on PyPI.
