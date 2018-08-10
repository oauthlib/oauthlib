===================
Creating a Provider
===================

OAuthLib is a dependency free library that may be used with any web
framework. That said, there are framework specific helper libraries
to make your life easier.

- Django `django-oauth-toolkit`_
- Flask `flask-oauthlib`_
- Pyramid `pyramid-oauthlib`_
- Bottle `bottle-oauthlib`_

If there is no support for your favourite framework and you are interested
in providing it then you have come to the right place. OAuthLib can handle
the OAuth logic and leave you to support a few framework and setup specific
tasks such as marshalling request objects into URI, headers and body arguments
as well as provide an interface for a backend to store tokens, clients, etc.

.. _`django-oauth-toolkit`: https://github.com/evonove/django-oauth-toolkit
.. _`flask-oauthlib`: https://github.com/lepture/flask-oauthlib
.. _`pyramid-oauthlib`: https://github.com/tilgovi/pyramid-oauthlib
.. _`bottle-oauthlib`: https://github.com/thomsonreuters/bottle-oauthlib

.. contents:: Tutorial Contents
    :depth: 3

1. Create your datastore models
-------------------------------

These models will represent various OAuth specific concepts. There are a few
important links between them that the security of OAuth is based on. Below
is a suggestion for models and why you need certain properties. There is
also example Django model fields which should be straightforward to
translate to other ORMs such as SQLAlchemy and the Appengine Datastore.

User (or Resource Owner)
^^^^^^^^^^^^^^^^^^^^^^^^

The user of your site which resources might be accessed by clients upon
authorization from the user. In our example we will re-use the User
model provided in django.contrib.auth.models. How the user authenticates
is orthogonal from OAuth and may be any way you prefer::

    from django.contrib.auth.models import User

Client (or Consumer)
^^^^^^^^^^^^^^^^^^^^

The client interested in accessing protected resources.

**Client Identifier**:

    Required. The identifier the client will use during the OAuth
    workflow. Structure is up to you and may be a simple UUID.

    .. code-block:: python

        client_id = django.db.models.CharField(max_length=100, unique=True)

**User**:

    Recommended. It is common practice to link each client with one of
    your existing users. Whether you do associate clients and users or
    not, ensure you are able to protect yourself against malicious
    clients.

    .. code-block:: python

        user = django.db.models.ForeignKey(User)

**Grant Type**:

    Required. The grant type the client may utilize. This should only be
    one per client as each grant type has different security properties
    and it is best to keep them separate to avoid mistakes.

    .. code-block:: python

        # max_length and choices depend on which response types you support
        grant_type = django.db.models.CharField(max_length=18,
        choices=[('authorization_code', 'Authorization code')])

**Response Type**:

    Required, if using a grant type with an associated response type
    (eg. Authorization Code Grant) or using a grant which only utilizes
    response types (eg. Implicit Grant).

    .. code-block:: python

        # max_length and choices depend on which response types you support
        response_type = django.db.models.CharField(max_length=4,
        choices=[('code', 'Authorization code')])

**Scopes**:

    Required. The list of scopes the client may request access to. If
    you allow multiple types of grants this will vary related to their
    different security properties. For example, the Implicit Grant might
    only allow read-only scopes but the Authorization Grant also allow
    writes.

    .. code-block:: python

        # You could represent it either as a list of keys or by serializing
        # the scopes into a string.
        scopes = django.db.models.TextField()

        # You might also want to mark a certain set of scopes as default
        # scopes in case the client does not specify any in the authorization
        default_scopes = django.db.models.TextField()

**Redirect URIs**:

    These are the absolute URIs that a client may use to redirect to after
    authorization. You should never allow a client to redirect to a URI
    that has not previously been registered.

    .. code-block:: python

        # You could represent the URIs either as a list of keys or by
        # serializing them into a string.
        redirect_uris = django.db.models.TextField()

        # You might also want to mark a certain URI as default in case the
        # client does not specify any in the authorization
        default_redirect_uri = django.db.models.TextField()

Bearer Token (OAuth 2 Standard Token)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The most common type of OAuth 2 token. Through the documentation this
will be considered an object with several properties, such as token type
and expiration date, and distinct from the access token it contains.
Think of OAuth 2 tokens as containers and access tokens and refresh
tokens as text.

**Client**:

    Association with the client to whom the token was given.

    .. code-block:: python

        client = django.db.models.ForeignKey(Client)

**User**:

    Association with the user to which protected resources this token
    grants access.

    .. code-block:: python

        user = django.db.models.ForeignKey(User)

**Scopes**:

    Scopes to which the token is bound. Attempt to access protected
    resources outside these scopes will be denied.

    .. code-block:: python

        # You could represent it either as a list of keys or by serializing
        # the scopes into a string.
        scopes = django.db.models.TextField()

**Access Token**:

    An unguessable unique string of characters.

    .. code-block:: python

        access_token = django.db.models.CharField(max_length=100, unique=True)

**Refresh Token**:

    An unguessable unique string of characters. This token is only
    supplied to confidential clients. For example the Authorization Code
    Grant or the Resource Owner Password Credentials Grant.

    .. code-block:: python

        refresh_token = django.db.models.CharField(max_length=100, unique=True)

**Expiration time**:

    Exact time of expiration. Commonly this is one hour after creation.

    .. code-block:: python

        expires_at = django.db.models.DateTimeField()

Authorization Code
^^^^^^^^^^^^^^^^^^

This is specific to the Authorization Code grant and represent the
temporary credential granted to the client upon successful
authorization. It will later be exchanged for an access token, when that
is done it should cease to exist. It should have a limited life time,
less than ten minutes. This model is similar to the Bearer Token as it
mainly acts a temporary storage of properties to later be transferred to
the token.

**Client**:

    Association with the client to whom the token was given.

    .. code-block:: python

        client = django.db.models.ForeignKey(Client)

**User**:

    Association with the user to which protected resources this token
    grants access.

    .. code-block:: python

        user = django.db.models.ForeignKey(User)

**Scopes**:

    Scopes to which the token is bound. Attempt to access protected
    resources outside these scopes will be denied.

    .. code-block:: python

        # You could represent it either as a list of keys or by serializing
        # the scopes into a string.
        scopes = django.db.models.TextField()

**Authorization Code**:

    An unguessable unique string of characters.

    .. code-block:: python

        code = django.db.models.CharField(max_length=100, unique=True)

**Expiration time**:

    Exact time of expiration. Commonly this is under ten minutes after
    creation.

    .. code-block:: python

        expires_at = django.db.models.DateTimeField()

2. Implement a validator
------------------------

The majority of the work involved in implementing an OAuth 2 provider
relates to mapping various validation and persistence methods to a storage
backend. The not very accurately named interface you will need to implement
is called a :doc:`RequestValidator <validator>` (name suggestions welcome).

An example of a very basic implementation of the validate_client_id method
can be seen below.

.. code-block:: python

    from oauthlib.oauth2 import RequestValidator

    # From the previous section on models
    from my_models import Client

    class MyRequestValidator(RequestValidator):

        def validate_client_id(self, client_id, request):
            try:
                Client.objects.get(client_id=client_id)
                return True
            except Client.DoesNotExist:
                return False

The full API you will need to implement is available in the
:doc:`RequestValidator <validator>` section. You might not need to implement
all methods depending on which grant types you wish to support. A skeleton
validator listing the methods required for the WebApplicationServer is
available in the `examples`_ folder on GitHub.

..  _`examples`: https://github.com/oauthlib/oauthlib/blob/master/examples/skeleton_oauth2_web_application_server.py

Relevant sections include:

.. toctree::
    :maxdepth: 1

    validator
    security


3. Create your composite endpoint
---------------------------------

Each of the endpoints can function independently from each other, however
for this example it is easier to consider them as one unit. An example of a
pre-configured all-in-one Authorization Code Grant endpoint is given below.

.. code-block:: python

    # From the previous section on validators
    from my_validator import MyRequestValidator

    from oauthlib.oauth2 import WebApplicationServer

    validator = MyRequestValidator()
    server = WebApplicationServer(validator)

Relevant sections include:

.. toctree::
    :maxdepth: 1

    preconfigured_servers


4. Create your endpoint views
-----------------------------

We are implementing support for the Authorization Code Grant and will
therefore need two views for the authorization, pre- and post-authorization
together with the token view. We also include an error page to redirect
users to if the client supplied invalid credentials in their redirection,
for example an invalid redirect URI.

The example using Django but should be transferable to any framework.

.. code-block:: python

    # Handles GET and POST requests to /authorize
    class AuthorizationView(View):

        def __init__(self):
            # Using the server from previous section
            self._authorization_endpoint = server
    
        def get(self, request):
            # You need to define extract_params and make sure it does not
            # include file like objects waiting for input. In Django this
            # is request.META['wsgi.input'] and request.META['wsgi.errors']
            uri, http_method, body, headers = extract_params(request)
    
            try:
                scopes, credentials = self._authorization_endpoint.validate_authorization_request(
                    uri, http_method, body, headers)
    
                # Not necessarily in session but they need to be
                # accessible in the POST view after form submit.
                request.session['oauth2_credentials'] = credentials
    
                # You probably want to render a template instead.
                response = HttpResponse()
                response.write('<h1> Authorize access to %s </h1>' % client_id)
                response.write('<form method="POST" action="/authorize">')
                for scope in scopes or []:
                    response.write('<input type="checkbox" name="scopes" ' + 
                    'value="%s"/> %s' % (scope, scope))
                    response.write('<input type="submit" value="Authorize"/>')
                return response
    
            # Errors that should be shown to the user on the provider website
            except errors.FatalClientError as e:
                return response_from_error(e)
    
            # Errors embedded in the redirect URI back to the client
            except errors.OAuth2Error as e:
                return HttpResponseRedirect(e.in_uri(e.redirect_uri))
    
        @csrf_exempt
        def post(self, request):
            uri, http_method, body, headers = extract_params(request)
    
            # The scopes the user actually authorized, i.e. checkboxes
            # that were selected.
            scopes = request.POST.getlist(['scopes'])
    
            # Extra credentials we need in the validator
            credentials = {'user': request.user}
    
            # The previously stored (in authorization GET view) credentials
            credentials.update(request.session.get('oauth2_credentials', {}))
    
            try:
                headers, body, status = self._authorization_endpoint.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
                return response_from_return(headers, body, status)
    
            except errors.FatalClientError as e:
                return response_from_error(e)

    # Handles requests to /token
    class TokenView(View):

        def __init__(self):
            # Using the server from previous section
            self._token_endpoint = server

        def post(self, request):
            uri, http_method, body, headers = extract_params(request)

            # If you wish to include request specific extra credentials for
            # use in the validator, do so here.
            credentials = {'foo': 'bar'}

            headers, body, status = self._token_endpoint.create_token_response(
                    uri, http_method, body, headers, credentials)

            # All requests to /token will return a json response, no redirection.
            return response_from_return(headers, body, status)

    def response_from_return(headers, body, status):
        response = HttpResponse(content=body, status=status)
        for k, v in headers.items():
            response[k] = v
        return response

    def response_from_error(e)
        return HttpResponseBadRequest('Evil client is unable to send a proper request. Error is: ' + e.description)


5. Protect your APIs using scopes
---------------------------------

Let's define a decorator we can use to protect the views.

.. code-block:: python

    class OAuth2ProviderDecorator(object):

        def __init__(self, resource_endpoint):
            self._resource_endpoint = resource_endpoint

        def protected_resource_view(self, scopes=None):
            def decorator(f):
                @functools.wraps(f)
                def wrapper(request):
                    # Get the list of scopes
                    try:
                        scopes_list = scopes(request)
                    except TypeError:
                        scopes_list = scopes

                    uri, http_method, body, headers = extract_params(request)

                    valid, r = self._resource_endpoint.verify_request(
                            uri, http_method, body, headers, scopes_list)

                    # For convenient parameter access in the view
                    add_params(request, {
                        'client': r.client,
                        'user': r.user,
                        'scopes': r.scopes
                    })
                    if valid:
                        return f(request)
                    else:
                        # Framework specific HTTP 403
                        return HttpResponseForbidden()
                return wrapper
            return decorator

    provider = OAuth2ProviderDecorator(server)

At this point you are ready to protect your API views with OAuth. Take some
time to come up with a good set of scopes as they can be very powerful in
controlling access.

.. code-block:: python

    @provider.protected_resource_view(scopes=['images'])
    def i_am_protected(request, client, resource_owner):
        # One of your many OAuth 2 protected resource views
        # Returns whatever you fancy
        # May be bound to various scopes of your choosing
        return HttpResponse('pictures of cats')

The set of scopes that protects a view may also be dynamically configured
at runtime by a function, rather then by a list.

.. code-block:: python

    def dynamic_scopes(request):
        # Place code here to dynamically determine the scopes
        # and return as a list
        return ['images']

    @provider.protected_resource_view(scopes=dynamic_scopes)
    def i_am_also_protected(request, client, resource_owner, **kwargs)
        # A view that has its views functionally set.
        return HttpResponse('pictures of cats')

6. Let us know how it went!
---------------------------

Drop a line in our `Gitter OAuthLib community`_ or open a `GitHub issue`_ =)

.. _`Gitter OAuthLib community`: https://gitter.im/oauthlib/Lobby
.. _`GitHub issue`: https://github.com/oauthlib/oauthlib/issues/new

If you run into issues it can be helpful to enable debug logging.

.. code-block:: python

    import logging
    import sys
    log = logging.getLogger('oauthlib')
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.setLevel(logging.DEBUG)
