=======
History
=======

Unreleased
----------

* Cache OAuth access tokens for their advertised lifetime and refresh them safely across threads.
* Retry an HTTP 401 once with a fresh token and redact authorization values from request logs.
* ``servicepytan_connect`` now returns a read-only ``Mapping`` with process-local token state; do not mutate, serialize, copy, or share the connection across processes.
* A second HTTP 401 after the fresh-token replay is raised immediately instead of entering the generic request retry loop.
* ``get_auth_token`` may return a cached token until its safety window begins (up to 60 seconds before its advertised expiration).

0.1.0 (2022-03-27)
------------------

* First release on PyPI.
