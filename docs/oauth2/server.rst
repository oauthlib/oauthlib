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

1. OAuth2.0 Provider flows
-------------------------------

OAuthLib interface between web framework and provider implementation are not always easy to follow, it's why a graph below has been done to better understand the implication of OAuthLib in the request's  lifecycle.


.. graphviz:: oauth2provider-legend.dot
.. graphviz:: oauth2provider-server.dot


2. Create your datastore models
-------------------------------

These models will represent various OAuth specific concepts. There are a few
important links between them that the security of OAuth is based on. Below
is a suggestion for models and why you need certain properties. There is
also example SQLAlchemy 2.0 model fields (``Mapped`` / ``mapped_column``,
usable with SQLAlchemy's ``AsyncSession``) which should be straightforward to
translate to other ORMs such as Django and the Appengine Datastore.

User (or Resource Owner)
^^^^^^^^^^^^^^^^^^^^^^^^

The user of your site which resources might be accessed by clients upon
authorization from the user. In our example we will use a minimal User
model. How the user authenticates is orthogonal from OAuth and may be any
way you prefer::

    import datetime
    from typing import Optional

    from sqlalchemy import DateTime, ForeignKey, String, Text
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    class Base(DeclarativeBase):
        pass

    class User(Base):
        __tablename__ = 'users'

        id: Mapped[int] = mapped_column(primary_key=True)
        username: Mapped[str] = mapped_column(String(150), unique=True)

Client (or Consumer)
^^^^^^^^^^^^^^^^^^^^

The client interested in accessing protected resources.

**Client Identifier**:

    Required. The identifier the client will use during the OAuth
    workflow. Structure is up to you and may be a simple UUID.

    .. code-block:: python

        client_id: Mapped[str] = mapped_column(String(100), unique=True)

**User**:

    Recommended. It is common practice to link each client with one of
    your existing users. Whether you do associate clients and users or
    not, ensure you are able to protect yourself against malicious
    clients.

    .. code-block:: python

        user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))

**Grant Type**:

    Required. The grant type the client may utilize. This should only be
    one per client as each grant type has different security properties
    and it is best to keep them separate to avoid mistakes.

    .. code-block:: python

        # max_length and choices depend on which response types you support
        # e.g. 'authorization_code'
        grant_type: Mapped[str] = mapped_column(String(18))

**Response Type**:

    Required, if using a grant type with an associated response type
    (eg. Authorization Code Grant) or using a grant which only utilizes
    response types (eg. Implicit Grant).

    .. code-block:: python

        # max_length and choices depend on which response types you support
        # e.g. 'code'
        response_type: Mapped[str] = mapped_column(String(4))

**Scopes**:

    Required. The list of scopes the client may request access to. If
    you allow multiple types of grants this will vary related to their
    different security properties. For example, the Implicit Grant might
    only allow read-only scopes but the Authorization Grant also allow
    writes.

    .. code-block:: python

        # You could represent it either as a list of keys or by serializing
        # the scopes into a string.
        scopes: Mapped[str] = mapped_column(Text)

        # You might also want to mark a certain set of scopes as default
        # scopes in case the client does not specify any in the authorization
        default_scopes: Mapped[str] = mapped_column(Text)

**Redirect URIs**:

    These are the absolute URIs that a client may use to redirect to after
    authorization. You should never allow a client to redirect to a URI
    that has not previously been registered.

    .. code-block:: python

        # You could represent the URIs either as a list of keys or by
        # serializing them into a string.
        redirect_uris: Mapped[str] = mapped_column(Text)

        # You might also want to mark a certain URI as default in case the
        # client does not specify any in the authorization
        default_redirect_uri: Mapped[Optional[str]] = mapped_column(Text)

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

        client_id: Mapped[str] = mapped_column(ForeignKey('clients.client_id'))

**User**:

    Association with the user to which protected resources this token
    grants access.

    .. code-block:: python

        user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))

**Scopes**:

    Scopes to which the token is bound. Attempt to access protected
    resources outside these scopes will be denied.

    .. code-block:: python

        # You could represent it either as a list of keys or by serializing
        # the scopes into a string.
        scopes: Mapped[str] = mapped_column(Text)

**Access Token**:

    An unguessable unique string of characters.

    .. code-block:: python

        access_token: Mapped[str] = mapped_column(String(100), unique=True)

**Refresh Token**:

    An unguessable unique string of characters. This token is only
    supplied to confidential clients. For example the Authorization Code
    Grant or the Resource Owner Password Credentials Grant.

    .. code-block:: python

        refresh_token: Mapped[Optional[str]] = mapped_column(String(100), unique=True)

**Expiration time**:

    Exact time of expiration. Commonly this is one hour after creation.

    .. code-block:: python

        expires_at: Mapped[datetime.datetime] = mapped_column(DateTime)

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

        client_id: Mapped[str] = mapped_column(ForeignKey('clients.client_id'))

**User**:

    Association with the user to which protected resources this token
    grants access.

    .. code-block:: python

        user_id: Mapped[int] = mapped_column(ForeignKey('users.id'))

**Scopes**:

    Scopes to which the token is bound. Attempt to access protected
    resources outside these scopes will be denied.

    .. code-block:: python

        # You could represent it either as a list of keys or by serializing
        # the scopes into a string.
        scopes: Mapped[str] = mapped_column(Text)

**Redirect URI**:

    If the client specifies a redirect_uri when obtaining code then that
    redirect URI must be bound to the code and verified equal in this
    method, according to RFC 6749 section 4.1. This field holds that
    bound value.

    .. code-block:: python

        redirect_uri: Mapped[str] = mapped_column(Text)

**Authorization Code**:

    An unguessable unique string of characters.

    .. code-block:: python

        code: Mapped[str] = mapped_column(String(100), unique=True)

**Expiration time**:

    Exact time of expiration. Commonly this is under ten minutes after
    creation.

    .. code-block:: python

        expires_at: Mapped[datetime.datetime] = mapped_column(DateTime)

**PKCE Challenge (optional)**

    If you want to support PKCE, you have to associate a `code_challenge`
    and a `code_challenge_method` to the actual Authorization Code.

    .. code-block:: python

        challenge: Mapped[Optional[str]] = mapped_column(String(128))
        challenge_method: Mapped[Optional[str]] = mapped_column(String(6))


3. Implement a validator
------------------------

The majority of the work involved in implementing an OAuth 2 provider
relates to mapping various validation and persistence methods to a storage
backend. The not very accurately named interface you will need to implement
is called a :doc:`RequestValidator <validator>` (name suggestions welcome).

.. note::

    Validator methods are coroutines and must be declared with ``async def``.
    OAuthLib awaits every one of them, so they can use an async database
    driver such as SQLAlchemy's ``AsyncSession`` without blocking the event
    loop. Overriding one with a plain ``def`` raises ``TypeError`` as soon as
    your subclass is defined. This applies to the OpenID Connect and Device
    Authorization (RFC 8628) validators as well.

    A complete, runnable application built on FastAPI and an async SQLAlchemy
    session is available as ``examples/fastapi_async_sqlalchemy.py`` in the
    repository.

An example of a very basic implementation of the validate_client_id method
can be seen below.

.. code-block:: python

    from sqlalchemy import select
    from sqlalchemy.ext.asyncio import AsyncSession

    from oauthlib.oauth2 import RequestValidator

    # From the previous section on models
    from my_models import Client

    class MyRequestValidator(RequestValidator):

        def __init__(self, session: AsyncSession):
            super().__init__()
            self.session = session

        async def validate_client_id(self, client_id, request):
            client = await self.session.scalar(
                select(Client).where(Client.client_id == client_id))
            if client is None:
                return False
            request.client = client
            return True

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


4. Create your composite endpoint
---------------------------------

Each of the endpoints can function independently from each other, however
for this example it is easier to consider them as one unit. An example of a
pre-configured all-in-one Authorization Code Grant endpoint is given below.
The validator is bound to a database session, so a new server is built for
every request around that request's session (construction does no I/O, so
this is cheap).

.. code-block:: python

    from fastapi import Depends
    from sqlalchemy.ext.asyncio import (
        AsyncSession, async_sessionmaker, create_async_engine,
    )

    # From the previous section on validators
    from my_validator import MyRequestValidator

    from oauthlib.oauth2 import WebApplicationServer

    engine = create_async_engine('postgresql+asyncpg://user:pass@host/db')
    SessionLocal = async_sessionmaker(engine, expire_on_commit=False)

    async def get_session():
        async with SessionLocal() as session:
            yield session  # uncommitted work is rolled back on close

    def get_server(session: AsyncSession = Depends(get_session)):
        return WebApplicationServer(MyRequestValidator(session))

Relevant sections include:

.. toctree::
    :maxdepth: 1

    preconfigured_servers


5. Create your endpoint views
-----------------------------

We are implementing support for the Authorization Code Grant and will
therefore need two views for the authorization, pre- and post-authorization
together with the token view. We also include an error page to redirect
users to if the client supplied invalid credentials in their redirection,
for example an invalid redirect URI.

The example uses FastAPI but should be transferable to any async framework.
All endpoint methods are coroutines and must be awaited. Commit the session
before returning a response, so a client never receives a code or token that
failed to persist.

.. code-block:: python

    from fastapi import Depends, FastAPI, Request
    from fastapi.responses import HTMLResponse, RedirectResponse, Response
    from sqlalchemy.ext.asyncio import AsyncSession
    from oauthlib.oauth2 import FatalClientError, OAuth2Error, WebApplicationServer

    app = FastAPI()

    async def extract_params(request: Request):
        # Starlette request -> oauthlib's (uri, http_method, body, headers)
        body = await request.body()
        return (str(request.url), request.method,
                body.decode('utf-8') or None, dict(request.headers))

    # Handles GET requests to /authorize
    @app.get('/authorize')
    async def authorize_get(request: Request,
                            server: WebApplicationServer = Depends(get_server)):
        uri, http_method, body, headers = await extract_params(request)

        try:
            scopes, credentials = await server.validate_authorization_request(
                uri, http_method, body, headers)

            # Not necessarily in session but they need to be
            # accessible in the POST view after form submit.
            # (request.session requires Starlette's SessionMiddleware)
            request.session['oauth2_credentials'] = credentials

            # You probably want to render a template instead.
            response = '<h1> Authorize access to %s </h1>' % credentials['client_id']
            response += '<form method="POST" action="/authorize">'
            for scope in scopes or []:
                response += ('<input type="checkbox" name="scopes" ' +
                             'value="%s"/> %s' % (scope, scope))
            response += '<input type="submit" value="Authorize"/>'
            return HTMLResponse(response)

        # Errors that should be shown to the user on the provider website
        except FatalClientError as e:
            return response_from_error(e)

        # Errors embedded in the redirect URI back to the client
        except OAuth2Error as e:
            return RedirectResponse(e.in_uri(e.redirect_uri))

    # Handles POST requests to /authorize
    @app.post('/authorize')
    async def authorize_post(request: Request,
                             session: AsyncSession = Depends(get_session),
                             server: WebApplicationServer = Depends(get_server)):
        uri, http_method, body, headers = await extract_params(request)

        # The scopes the user actually authorized, i.e. checkboxes
        # that were selected.
        scopes = (await request.form()).getlist('scopes')

        # Extra credentials we need in the validator
        # (request.user requires Starlette's AuthenticationMiddleware)
        credentials = {'user': request.user}

        # The previously stored (in authorization GET view) credentials
        credentials.update(request.session.get('oauth2_credentials', {}))

        try:
            headers, body, status = await server.create_authorization_response(
                uri, http_method, body, headers, scopes, credentials)
            await session.commit()
            return response_from_return(headers, body, status)

        except FatalClientError as e:
            return response_from_error(e)

    # Handles requests to /token
    @app.post('/token')
    async def token(request: Request,
                    session: AsyncSession = Depends(get_session),
                    server: WebApplicationServer = Depends(get_server)):
        uri, http_method, body, headers = await extract_params(request)

        # If you wish to include request specific extra credentials for
        # use in the validator, do so here.
        credentials = {'foo': 'bar'}

        headers, body, status = await server.create_token_response(
                uri, http_method, body, headers, credentials)
        if status == 200:
            await session.commit()

        # All requests to /token will return a json response, no redirection.
        return response_from_return(headers, body, status)

    def response_from_return(headers, body, status):
        return Response(content=body or '', status_code=status, headers=headers)

    def response_from_error(e):
        return Response('Evil client is unable to send a proper request. Error is: ' + e.description,
                        status_code=400)


6. Protect your APIs using scopes
---------------------------------

Let's define a dependency we can use to protect the views.

.. code-block:: python

    from fastapi import HTTPException

    def protected_resource(scopes=None):
        async def dependency(request: Request,
                             server: WebApplicationServer = Depends(get_server)):
            # Get the list of scopes
            try:
                scopes_list = scopes(request)
            except TypeError:
                scopes_list = scopes

            uri, http_method, body, headers = await extract_params(request)

            valid, r = await server.verify_request(
                    uri, http_method, body, headers, scopes_list)

            if not valid:
                # Framework specific HTTP 403
                raise HTTPException(403)

            # For convenient parameter access in the view:
            # r.client, r.user and r.scopes
            return r
        return dependency

At this point you are ready to protect your API views with OAuth. Take some
time to come up with a good set of scopes as they can be very powerful in
controlling access.

.. code-block:: python

    @app.get('/cats')
    async def i_am_protected(oauth=Depends(protected_resource(scopes=['images']))):
        # One of your many OAuth 2 protected resource views
        # Returns whatever you fancy
        # May be bound to various scopes of your choosing
        return 'pictures of cats'

The set of scopes that protects a view may also be dynamically configured
at runtime by a function, rather then by a list.

.. code-block:: python

    def dynamic_scopes(request):
        # Place code here to dynamically determine the scopes
        # and return as a list
        return ['images']

    @app.get('/more-cats')
    async def i_am_also_protected(oauth=Depends(protected_resource(scopes=dynamic_scopes))):
        # A view that has its scopes functionally set.
        return 'pictures of cats'

7. Let us know how it went!
---------------------------

Drop a line in our `Gitter OAuthLib community`_ or open a `GitHub issue`_ =)

.. _`Gitter OAuthLib community`: https://gitter.im/oauthlib/Lobby
.. _`GitHub issue`: https://github.com/oauthlib/oauthlib/issues/new

If you run into issues it can be helpful to enable debug logging.

.. code-block:: python

    import logging
    import oauthlib
    import sys

    oauthlib.set_debug(True)
    log = logging.getLogger('oauthlib')
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.setLevel(logging.DEBUG)
