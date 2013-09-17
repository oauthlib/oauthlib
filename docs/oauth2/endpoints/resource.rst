======================
Resource authorization
======================

Resource endpoints verify that the token presented is valid and granted access
to the scopes associated with the resource in question.

**Request Verfication**
    Each view may set certain scopes under which it is bound. Only requests
    that present an access token bound to the correct scopes may access the
    view. Access tokens are commonly embedded in the authorization header but
    may appear in the query or the body as well.

    .. code-block:: python

        # Initial setup
        from your_validator import your_validator
        server = WebApplicationServer(your_validator)

        # Per view scopes
        required_scopes = ['https://example.com/userProfile']

        # Validate request
        uri = 'https://example.com/userProfile?access_token=sldafh309sdf'
        headers, body, http_method = {}, '', 'GET'

        valid, oauthlib_request = server.verify_request(
            uri, http_method, body, headers, required_scopes)

        # oauthlib_request has a few convenient attributes set such as
        # oauthlib_request.client = the client associated with the token
        # oauthlib_request.user = the user associated with the token
        # oauthlib_request.scopes = the scopes bound to this token

        if valid:
            # return the protected resource / view
        else:
            # return an http forbidden 403

.. autoclass:: oauthlib.oauth2.ResourceEndpoint
    :members:
