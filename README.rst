OAuthLib
========

*A generic, spec-compliant, thorough implementation of the OAuth request-signing
logic.*

.. image:: https://secure.travis-ci.org/idangazit/oauthlib.png?branch=master

OAuth often seems complicated and difficult-to-implement. There are several
prominent libraries for signing OAuth requests, but they all suffer from one or
both of the following:

1. They predate the `OAuth 1.0 spec`_, AKA RFC 5849.
2. They assume the usage of a specific HTTP request library.

.. _`OAuth 1.0 spec`: http://tools.ietf.org/html/rfc5849

OAuthLib is a generic utility which implements the logic of OAuth without
assuming a specific HTTP request object. Use it to graft OAuth support onto your
favorite HTTP library. If you're a maintainer of such a library, write a thin
veneer on top of OAuthLib and get OAuth support for very little effort.

Interested in making OAuth requests?
------------------------------------

Then you might be more interested in using `requests`_ which has OAuthLib 
powered OAuth support built-in. See the `requests OAuth examples`_ for
how you can get started.

.. _`requests`: https://github.com/kennethreitz/requests
.. _`requests OAuth examples`: http://docs.python-requests.org/en/latest/user/quickstart/#oauth-authentication 

License
-------

OAuthLib is yours to use and abuse according to the terms of the BSD license.
Check the LICENSE file for full details.



Changelog
---------

*OAuthLib is in active development, with most of OAuth1 complete and OAuth2
already in the works.*

0.3.2: Fixed #62, all Python 3 tests pass.

0.3.1: Python 3.1, 3.2, 3.3 support (experimental)

0.3.0: Initial OAuth 2 client support

0.2.1: Exclude non urlencoded bodies during request verification

0.2.0: OAuth provider support

0.1.4: soft dependency on PyCrypto  

0.1.3: use python-rsa instead of pycrypto.

0.1.1 / 0.1.2: Fix installation of pycrypto dependency.

0.1.0: OAuth 1 client functionality seems to be working. Hooray!

0.0.x: In the beginning, there was the word.
