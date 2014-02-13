Provider Endpoints
==================

Endpoints in OAuth 2 are targets with a specific responsibility and often
associated with a particular URL. Because of this the word endpoint might be
used interchangably from the endpoint url.

The main three responsibilities in an OAuth 2 flow is to authorize access to a
certain users resources to a client, to supply said client with a token
embodying this authorization and to verify that the token is valid when the
client attempts to access the user resources on their behalf.

.. toctree::
    :maxdepth: 2

    authorization
    token
    resource
    revocation

There are three different endpoints, the authorization endpoint which mainly
handles user authorization, the token endpoint which provides tokens and the
resource endpoint which provides access to protected resources. It is to the
endpoints you will feed requests and get back an almost complete response. This
process is simplified for you using a decorator such as the django one described
later.

The main purpose of the endpoint in OAuthLib is to figure out which grant type
or token to dispatch the request to.
