Frequently asked questions
==========================

How do I enable logging for OAuthLib?
-------------------------------------

    See :doc:`error_reporting`.

What parts of OAuth 1 & 2 are supported?
----------------------------------------

    See :doc:`feature_matrix`.

OAuth 1 with RSA-SHA1 signatures says "could not import cryptography". What should I do?
----------------------------------------------------------------------------------

    Install cryptography via pip.

.. code-block:: sh

    $ pip install cryptography

OAuth 2 ServiceApplicationClient and OAuth 1 with RSA-SHA1 signatures say "could not import jwt". What should I do?
-------------------------------------------------------------------------------------------------------------------

    Install pyjwt and cryptography with pip.

.. code-block:: sh

    $ pip install pyjwt cryptography

What does ValueError `Only unicode objects are escapable. Got one of type X.` mean?
-----------------------------------------------------------------------------------

   OAuthLib uses unicode everywhere and when creating a OAuth 1 signature
   a number of parameters need to be percent encoded (aka escaped). At least
   one parameter could not be encoded. Usually because `None` or a non UTF-8 
   encoded string was supplied.

What does ValueError `Error trying to decode a non urlencoded string` mean?
---------------------------------------------------------------------------

    You are trying to decode a response which is not properly encoded, e.g.
    include non percent encoded characters such as `£`. Which could be because
    it has already been decoded by your web framework. 
    
    If you believe it contains characters that should be excempt from this
    check please open an issue and state why.
    
     
What is the difference between a client and a consumer?
-------------------------------------------------------

    None, they both refer to the third-party accessing protected resources
    from an OAuth provider on behalf of a user. In order to do so they have
    to obtain authorization from said user, which is what the `Auth` in `OAuth`
    stands for.

How do I use OAuthLib with Google, Twitter and other providers?
---------------------------------------------------------------

    Most people will be using OAuthLib indirectly. Clients will want to look at
    `requests-oauthlib`_.
    
How do I use OAuthlib as a provider with Django, Flask and other web frameworks?
--------------------------------------------------------------------------------

    Providers using Django should seek out `django-oauth-toolkit`_
    and those using Flask `flask-oauthlib`_. For other frameworks,
    please get in touch by opening a `GitHub issue`_, on `G+`_ or
    on IRC #oauthlib irc.freenode.net.

What is the difference between authentication and authorization?
----------------------------------------------------------------

    See `difference`_.

Very briefly, what is the biggest difference between OAuth 1 and 2?
-------------------------------------------------------------------

    OAuth 2 is much simpler since it requires the use of TLS whereas OAuth 1
    had the requirement to work securely without TLS. To be secure without TLS
    OAuth 1 required each request to be signed which can be cumbersome.

Some argue OAuth 2 is worse than 1, is that true?
-------------------------------------------------

    Correctly implemented, OAuth 2 is better in many ways than OAuth 1. Getting
    it right is not trivial and a task OAuthLib aims to help make simple.

.. _`requests-oauthlib`: https://github.com/requests/requests-oauthlib
.. _`django-oauth-toolkit`: https://github.com/evonove/django-oauth-toolkit
.. _`flask-oauthlib`: https://github.com/lepture/flask-oauthlib
.. _`GitHub issue`: https://github.com/idan/oauthlib/issues/new
.. _`G+`: https://plus.google.com/communities/101889017375384052571
.. _`difference`: http://www.cyberciti.biz/faq/authentication-vs-authorization/
