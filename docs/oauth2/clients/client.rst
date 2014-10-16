=============
Using Clients
=============

OAuthLib supports all four core grant types defined in the OAuth 2 RFC and
will continue to add more as they are defined. For more information on how
to use them please browse the documentation for each client type below.

.. toctree::
    :maxdepth: 2

    baseclient
    webapplicationclient
    mobileapplicationclient
    legacyapplicationclient
    backendapplicationclient

**Existing libraries**
    If you are using the `requests`_ HTTP library you may be interested in using
    `requests-oauthlib`_ which provides an OAuth 2 Client. This client removes much
    of the boilerplate you might otherwise need to deal with when interacting
    with OAuthLib directly.

    If you are interested in integrating OAuth 2 support into your favourite
    HTTP library you might find the requests-oauthlib implementation interesting.

    .. _`requests`: https://github.com/kennethreitz/requests
    .. _`requests-oauthlib`: https://github.com/requests/requests-oauthlib
