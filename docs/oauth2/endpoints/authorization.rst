=============
Authorization
=============

Authorization can be either explicit or implicit. The former require the user to
actively authorize the client by being redirected to the authorization endpoint.
There he/she is usually presented by a form and asked to either accept or deny
access to certain scopes. These scopes can be thought of as Access Control Lists
that are tied to certain privileges and categories of resources, such as write
access to their status feed or read access to their profile. It is vital that
the implications of granting access to a certain scope is very clear in the
authorization form presented to the user. It is up to the provider to allow the
user agree to all, a few or none of the scopes. Being flexible here is a great
benefit to the user at the cost of added complexity in both the provider and
clients.

Implicit authorization happens when the authorization happens before the OAuth
flow, such as the user giving the client his/her password and username, or if
there is a very high level of trust between the user, client and provider and no
explicit authorization is necessary.

Examples of explicit authorization is the Authorization Code Grant and the
Implicit Grant.

Examples of implicit authorization is the Resource Owner Password Credentials
Grant and the Client Credentials Grant.

**Pre Authorization Request**
    OAuth is known for it's authorization page where the user accepts or denies
    access to a certain client and set of scopes. Before presenting the user
    with such a form you need to ensure the credentials the client supplied in
    the redirection to this page are valid.

    .. code-block:: python

        # Initial setup
        from your_validator import your_validator
        server = WebApplicationServer(your_validator)

        # Validate request
        uri = 'https://example.com/authorize?client_id=foo&state=xyz
        headers, body, http_method = {}, '', 'GET'

        from oauthlib.oauth2 import FatalClientError
        from your_framework import redirect
        try:
            scopes, credentials = server.validate_authorization_request(
                uri, http_method, body, headers)
            # scopes will hold default scopes for client, i.e.
            ['https://example.com/userProfile', 'https://example.com/pictures']

            # credentials is a dictionary of
            {
                'client_id': 'foo',
                'redirect_uri': 'https://foo.com/welcome_back',
                'response_type': 'code',
                'state': 'randomstring',
            }
            # these credentials will be needed in the post authorization view and
            # should be persisted between. None of them are secret but take care
            # to ensure their integrity if embedding them in the form or cookies.
            from your_datastore import persist_credentials
            persist_credentials(credentials)

            # Present user with a nice form where client (id foo) request access to
            # his default scopes (omitted from request), after which you will
            # redirect to his default redirect uri (omitted from request).

        except FatalClientError as e:
            # this is your custom error page
            from your_view_helpers import error_to_response
            return error_to_response(e)


**Post Authorization Request**
    Generally, this is where you handle the submitted form. Rather than using
    ``validate_authorization_request`` we use ``create_authorization_response``
    which in the case of Authorization Code Grant embed an authorization code in
    the client provided redirect uri.

    .. code-block:: python

        # Initial setup
        from your_validator import your_validator
        server = WebApplicationServer(your_validator)

        # Validate request
        uri = 'https://example.com/post_authorize?client_id=foo
        headers, body, http_method = {}, '', 'GET'

        # Fetch the credentials saved in the pre authorization phase
        from your_datastore import fetch_credentials
        credentials = fetch_credentials()

        # Fetch authorized scopes from the request
        from your_framework import request
        scopes = request.POST.get('scopes')

        from oauthlib.oauth2 import FatalClientError, OAuth2Error
        from your_framework import http_response
        http_response(body, status=status, headers=headers)
        try:
            headers, body, status = server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            # headers = {'Location': 'https://foo.com/welcome_back?code=somerandomstring&state=xyz'}, this might change to include suggested headers related
            # to cache best practices etc.
            # body = '', this might be set in future custom grant types
            # status = 302, suggested HTTP status code

            return http_response(body, status=status, headers=headers)

        except FatalClientError as e:
            # this is your custom error page
            from your_view_helpers import error_to_response
            return error_to_response(e)

        except OAuth2Error as e:
            # Less grave errors will be reported back to client
            client_redirect_uri = credentials.get('redirect_uri')
            redirect(e.in_uri(client_redirect_uri))

.. autoclass:: oauthlib.oauth2.AuthorizationEndpoint
    :members:
