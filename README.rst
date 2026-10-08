============
servicepytan
============


.. image:: https://img.shields.io/pypi/v/servicepytan.svg
        :target: https://pypi.python.org/pypi/servicepytan

.. image:: https://img.shields.io/travis/elliotpalmer/servicepytan.svg
        :target: https://travis-ci.com/elliotpalmer/servicepytan

.. image:: https://readthedocs.org/projects/servicepytan/badge/?version=latest
        :target: https://servicepytan.readthedocs.io/en/latest/?version=latest
        :alt: Documentation Status




Python Library to make it easier to interact with the ServiceTitan API v2


* Free software: MIT license
* Documentation: https://servicepytan.readthedocs.io.


Features
--------

* Simple Syntax for getting data from standard RESTful endpoints from ServiceTitan
* Ability to extract custom report data and automatically make calls for additional data
* Thread-safe OAuth token reuse and automatic refresh for ServiceTitan connections

Credits
-------

This package was created with Cookiecutter_ and the `audreyr/cookiecutter-pypackage`_ project template.

.. _Cookiecutter: https://github.com/audreyr/cookiecutter
.. _`audreyr/cookiecutter-pypackage`: https://github.com/audreyr/cookiecutter-pypackage

HTTP timeouts and retries
-------------------------

API requests default to a 5-second connect timeout and a 60-second read timeout.
The read timeout limits silence between bytes, not total request or job duration.
Pass ``timeout=(5, 120)`` to ``request_json`` or an ``Endpoint`` method to allow a
longer response, including each page of an export.

GET, HEAD, OPTIONS and DELETE use thread-local connection pools and retry
connection/read failures and HTTP 502/503/504 with exponential backoff.
``request_json(..., retry_count=1)`` disables transport and rate-limit retries;
the default of 3 allows up to three transport attempts per send. Responses with
HTTP 429 can trigger up to two additional sends, respecting ``Retry-After``.
One token refresh and replay is allowed on HTTP 401, even with ``retry_count=1``.
Other HTTP errors fail immediately, preserving ``HTTPError.response``.

POST, PATCH and PUT use fresh connections. They retry only connect timeouts,
HTTP 429 and the single HTTP 401 token refresh. A read timeout, connection reset
or server error may happen after ServiceTitan applies a write, so the library
does not replay it. PUT is conservative because some ServiceTitan endpoints
add items rather than replace them. Callers must check remote state before
retrying an ambiguous write.

Catch ``requests.RequestException`` for transport failures: exhausted adapter
retries can raise ``ConnectionError`` even when caused by a read timeout.

Write redirects are rejected with ``HTTPError`` rather than followed, preventing
HTTP 307/308 from silently replaying a write. The exception retains the response.

Reports accept ``Report(category, report_id, timeout=(5, 120))`` for metadata and
data requests. ``get_data(timeout=(5, 180))`` and ``get_all_data(timeout=(5, 180))``
override that setting for data requests, including every page. The existing
``timeout_min`` argument is separate and does not set an HTTP timeout.
