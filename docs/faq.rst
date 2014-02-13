F.A.Q
=====

What parts of OAuth 1 & 2 are supported?
    See :doc:`feature_matrix`.

What is the difference between a client and a consumer?
    None, they both refer to the third-party accessing protected resources
    from an OAuth provider on behalf of a user. In order to do so they have
    to obtain authorization from said user, which is what the `Auth` in `OAuth`
    stands for.

How do I use OAuthLib with Google, Twitter and other providers?
    Most people will be using OAuthLib indirectly. Clients will want to look at
    `requests-oauthlib`_.
    
How do I use OAuthlib as a provider with Django, Flask and other web frameworks?
    Providers using Django should seek out `django-oauth-toolkit`_
    and those using Flask `flask-oauthlib`_. For other frameworks,
    please get in touch by opening a `GitHub issue`_, on `G+`_ or
    on IRC #oauthlib irc.freenode.net.

What is the difference between authentication and authorization?
    See `difference`_.

Very briefly, what is the biggest difference between OAuth 1 and 2?
    OAuth 2 is much simpler since it requires the use of TLS whereas OAuth 1
    had the requirement to work securely without TLS. To be secure without TLS
    OAuth 1 required each request to be signed which can be cumbersome.

Some argue OAuth 2 is worse than 1, is that true?
    Correctly implemented, OAuth 2 is better in many ways than OAuth 1. Getting
    it right is not trivial and a task OAuthLib aims to help make simple.

.. _`requests-oauthlib`: https://github.com/requests/requests-oauthlib
.. _`django-oauth-toolkit`: https://github.com/evonove/django-oauth-toolkit
.. _`flask-oauthlib`: https://github.com/lepture/flask-oauthlib
.. _`GitHub issue`: https://github.com/idan/oauthlib/issues/new
.. _`G+`: https://plus.google.com/communities/101889017375384052571
.. _`difference`: http://www.cyberciti.biz/faq/authentication-vs-authorization/
