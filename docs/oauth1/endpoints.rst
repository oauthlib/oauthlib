Provider endpoints
==================

.. contents:: OAuth 1 Provider Endpoints
    :depth: 3

Each endpoint is responsible for one step in the OAuth 1 workflow. They can be
used either independently or in a combination. They depend on the use of a
:doc:`validator`.

See :doc:`preconfigured_servers` for available composite endpoints/servers.

RequestTokenEndpoint
--------------------

.. autoclass:: oauthlib.oauth1.RequestTokenEndpoint
    :members:

AuthorizationEndpoint
---------------------

.. autoclass:: oauthlib.oauth1.AuthorizationEndpoint
    :members:

AccessTokenEndpoint
-------------------

.. autoclass:: oauthlib.oauth1.AccessTokenEndpoint
    :members:

ResourceEndpoint
----------------

.. autoclass:: oauthlib.oauth1.ResourceEndpoint
    :members:
