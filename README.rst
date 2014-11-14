OAuthLib
========

*A generic, spec-compliant, thorough implementation of the OAuth request-signing
logic.*

.. image:: https://travis-ci.org/idan/oauthlib.png?branch=master
  :target: https://travis-ci.org/idan/oauthlib
.. image:: https://coveralls.io/repos/idan/oauthlib/badge.png?branch=master
  :target: https://coveralls.io/r/idan/oauthlib


OAuth often seems complicated and difficult-to-implement. There are several
prominent libraries for handling OAuth requests, but they all suffer from one or
both of the following:

1. They predate the `OAuth 1.0 spec`_, AKA RFC 5849.
2. They predate the `OAuth 2.0 spec`_, AKA RFC 6749.
3. They assume the usage of a specific HTTP request library.

.. _`OAuth 1.0 spec`: http://tools.ietf.org/html/rfc5849
.. _`OAuth 2.0 spec`: http://tools.ietf.org/html/rfc6749

OAuthLib is a generic utility which implements the logic of OAuth without
assuming a specific HTTP request object or web framework. Use it to graft OAuth
client support onto your favorite HTTP library, or provider support onto your
favourite web framework. If you're a maintainer of such a library, write a thin
veneer on top of OAuthLib and get OAuth support for very little effort.


Documentation
--------------

Full documentation is available on `Read the Docs`_. All contributions are very
welcome! The documentation is still quite sparse, please open an issue for what
you'd like to know, or discuss it in our `G+ community`_, or even better, send a
pull request!

.. _`G+ community`: https://plus.google.com/communities/101889017375384052571
.. _`Read the Docs`: https://oauthlib.readthedocs.org/en/latest/index.html

Interested in making OAuth requests?
------------------------------------

Then you might be more interested in using `requests`_ which has OAuthLib
powered OAuth support provided by the `requests-oauthlib`_ library.

.. _`requests`: https://github.com/kennethreitz/requests
.. _`requests-oauthlib`: https://github.com/requests/requests-oauthlib

Which web frameworks are supported?
-----------------------------------

The following packages provide OAuth support using OAuthLib.

- For Django there is `django-oauth-toolkit`_, which includes `Django REST framework`_ support.
- For Flask there is `flask-oauthlib`_ and `Flask-Dance`_.

If you have written an OAuthLib package that supports your favorite framework,
please open a Pull Request, updating the documentation.

.. _`django-oauth-toolkit`: https://github.com/evonove/django-oauth-toolkit
.. _`flask-oauthlib`: https://github.com/lepture/flask-oauthlib
.. _`Django REST framework`: http://django-rest-framework.org
.. _`Flask-Dance`: https://github.com/singingwolfboy/flask-dance

Using OAuthLib? Please get in touch!
------------------------------------
Patching OAuth support onto an http request framework? Creating an OAuth
provider extension for a web framework? Simply using OAuthLib to Get Things Done
or to learn?

No matter which we'd love to hear from you in our `G+ community`_ or if you have
anything in particular you would like to have, change or comment on don't
hesitate for a second to send a pull request or open an issue. We might be quite
busy and therefore slow to reply but we love feedback!

Chances are you have run into something annoying that you wish there was
documentation for, if you wish to gain eternal fame and glory, and a drink if we
have the pleasure to run into eachother, please send a docs pull request =)

.. _`G+ community`: https://plus.google.com/communities/101889017375384052571

License
-------

OAuthLib is yours to use and abuse according to the terms of the BSD license.
Check the LICENSE file for full details.

Changelog
---------

*OAuthLib is in active development, with the core of both OAuth 1 and 2
completed, for providers as well as clients.* See `supported features`_ for
details.

.. _`supported features`: http://oauthlib.readthedocs.org/en/latest/feature_matrix.html

For a full changelog see ``CHANGELOG.rst``.
