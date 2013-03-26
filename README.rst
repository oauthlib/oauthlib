OAuthLib
========

*A generic, spec-compliant, thorough implementation of the OAuth request-signing
logic.*

.. image:: https://secure.travis-ci.org/idangazit/oauthlib.png?branch=master
  :target: https://travis-ci.org/idan/oauthlib

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

Documentation
--------------

Full documentation is available on `Read the Docs`_. All contributions are very welcome! The documentation is still quite sparse, please open an issue for what you'd like to know, or discuss it in our `G+ community`_, or even better, send a pull request!

.. _`G+ community`: https://plus.google.com/communities/101889017375384052571
.. _`Read the Docs`: https://oauthlib.readthedocs.org/en/latest/index.html

Interested in making OAuth requests?
------------------------------------

Then you might be more interested in using `requests`_ which has OAuthLib 
powered OAuth support provided by the `requests-oauthlib`_ library.

.. _`requests`: https://github.com/kennethreitz/requests
.. _`requests-oauthlib`: https://github.com/requests/requests-oauthlib

Using OAuthLib? Please get in touch!
------------------------------------
Patching OAuth support onto an http request framework? Creating an OAuth provider extension for a web framework? Simply using OAuthLib to Get Things Done or to learn? 

No matter which we'd love to hear from you in our `G+ community`_ or if you have anything in particular you would like to have, change or comment on don't hesitate for a second to send a pull request or open an issue. We might be quite busy and therefore slow to reply but we love feedback!

Chances are you have run into something annoying that you wish there was documentation for, if you wish to gain eternal fame and glory, and a drink if we have the pleasure to run into eachother, please send a docs pull request =)

.. _`G+ community`: https://plus.google.com/communities/101889017375384052571

License
-------

OAuthLib is yours to use and abuse according to the terms of the BSD license.
Check the LICENSE file for full details.



Changelog
---------

*OAuthLib is in active development, with most of OAuth1 complete and OAuth2
already in the works.*

0.4.0: OAuth 2 Provider support (experimental).

0.3.8: OAuth 2 Client now uses custom errors and raise on expire

0.3.7: OAuth 1 optional encoding of Client.sign return values

0.3.6: Revert default urlencoding.

0.3.5: Default unicode conversion (utf-8) and urlencoding of input.

0.3.4: A number of small features and bug fixes.

0.3.3: OAuth 1 Provider verify now return useful params

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
