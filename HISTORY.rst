=======
History
=======

Unreleased
----------

* Cache OAuth access tokens for their advertised lifetime and refresh them safely across threads.
* Retry an HTTP 401 once with a fresh token and redact authorization values from request logs.

0.1.0 (2022-03-27)
------------------

* First release on PyPI.
