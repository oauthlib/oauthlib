"""OAuth 2 authorization server on FastAPI + async SQLAlchemy 2.0.

A runnable reference for wiring the async oauthlib server into an asyncio
application:

* ``SQLAlchemyRequestValidator`` implements the (async) ``RequestValidator``
  interface on top of an ``AsyncSession``: every storage call is awaited, so
  the event loop is never blocked on the database.
* One ``AsyncSession`` (one transaction) per HTTP request. The validator and
  server are built per request around it (cheap: no I/O happens at
  construction) and the handler commits explicitly *before* returning, so a
  client never receives a token or code that failed to persist.
* Authorization codes and refresh tokens are *consumed atomically*
  (``DELETE ... RETURNING``) so concurrent requests cannot redeem the same
  code or refresh token twice.
* ``to_oauthlib`` / ``to_response`` adapt Starlette requests/responses to
  oauthlib's ``(uri, http_method, body, headers)`` calling convention.

Run it (``pip install -r examples/requirements.txt uvicorn``)::

    OAUTHLIB_INSECURE_TRANSPORT=1 uvicorn examples.fastapi_async_sqlalchemy:app

``DATABASE_URL`` selects the database (default: a local SQLite file). For
production use a server database such as PostgreSQL
(``postgresql+asyncpg://...``).

``OAUTHLIB_INSECURE_TRANSPORT`` allows plain http for local testing only;
never set it in production. The demo authenticates the resource owner with
an ``X-User`` header: replace ``current_user`` with your real login/session.
Client secrets are stored in plain text for brevity; hash them in production.
"""
from __future__ import annotations

import base64
import datetime
import hmac
import os
from contextlib import asynccontextmanager
from typing import Optional
from urllib.parse import unquote_plus

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import DateTime, String, Text, delete, event
from sqlalchemy.ext.asyncio import (
    AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from oauthlib.oauth2 import (
    FatalClientError, OAuth2Error, RequestValidator, WebApplicationServer,
)

DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite+aiosqlite:///./oauth_example.db')


# --------------------------------------------------------------------------
# Models
# --------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


class Client(Base):
    __tablename__ = 'oauth_clients'

    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    # None for public clients (e.g. SPAs / native apps), which must use PKCE.
    client_secret: Mapped[Optional[str]] = mapped_column(String(128))
    redirect_uris: Mapped[str] = mapped_column(Text)        # space separated
    default_scopes: Mapped[str] = mapped_column(Text)       # space separated
    allowed_scopes: Mapped[str] = mapped_column(Text)       # space separated

    @property
    def is_confidential(self):
        return self.client_secret is not None


class AuthorizationCode(Base):
    __tablename__ = 'oauth_authorization_codes'

    code: Mapped[str] = mapped_column(String(255), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(64), index=True)
    user: Mapped[str] = mapped_column(String(255))
    redirect_uri: Mapped[str] = mapped_column(Text)
    scopes: Mapped[str] = mapped_column(Text)
    code_challenge: Mapped[Optional[str]] = mapped_column(String(128))
    code_challenge_method: Mapped[Optional[str]] = mapped_column(String(10))
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime)


class Token(Base):
    __tablename__ = 'oauth_tokens'

    access_token: Mapped[str] = mapped_column(String(255), primary_key=True)
    refresh_token: Mapped[Optional[str]] = mapped_column(String(255), unique=True, index=True)
    client_id: Mapped[str] = mapped_column(String(64), index=True)
    user: Mapped[str] = mapped_column(String(255))
    scopes: Mapped[str] = mapped_column(Text)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime)


# --------------------------------------------------------------------------
# Request validator
# --------------------------------------------------------------------------

class SQLAlchemyRequestValidator(RequestValidator):
    """Authorization Code (+PKCE) and Refresh Token grants backed by SQLAlchemy.

    All methods are ``async def`` (required by oauthlib) and only *stage*
    changes in the session; the HTTP handler owns the transaction.
    """

    code_lifetime = datetime.timedelta(minutes=10)

    def __init__(self, session: AsyncSession):
        super().__init__()
        self.session = session

    async def _client(self, client_id):
        if not client_id:
            return None
        return await self.session.get(Client, client_id)

    # -- client authentication --------------------------------------------

    async def client_authentication_required(self, request, *args, **kwargs):
        # Public clients authenticate by client_id alone (and must use PKCE).
        client = await self._client(request.client_id)
        return client is None or client.is_confidential

    async def authenticate_client(self, request, *args, **kwargs):
        client_id, secret = request.client_id, request.client_secret
        auth = request.headers.get('Authorization', '')
        if auth.lower().startswith('basic '):
            try:
                decoded = base64.b64decode(auth[6:]).decode('utf-8')
                client_id, secret = (unquote_plus(p) for p in decoded.split(':', 1))
            except ValueError:
                return False
        client = await self._client(client_id)
        if client is None or not client.is_confidential or secret is None:
            return False
        if not hmac.compare_digest(client.client_secret.encode(), secret.encode()):
            return False
        request.client = client
        return True

    async def authenticate_client_id(self, client_id, request, *args, **kwargs):
        client = await self._client(client_id)
        if client is None or client.is_confidential:
            return False
        request.client = client
        return True

    # -- authorization request --------------------------------------------

    async def validate_client_id(self, client_id, request, *args, **kwargs):
        client = await self._client(client_id)
        if client is None:
            return False
        request.client = client
        return True

    async def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        client = await self._client(client_id)
        return client is not None and redirect_uri in client.redirect_uris.split()

    async def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        client = await self._client(client_id)
        uris = client.redirect_uris.split() if client else []
        return uris[0] if len(uris) == 1 else None

    async def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        return response_type == 'code'

    async def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        client = client or await self._client(client_id)
        return client is not None and set(scopes) <= set(client.allowed_scopes.split())

    async def get_default_scopes(self, client_id, request, *args, **kwargs):
        client = await self._client(client_id)
        return client.default_scopes.split() if client else []

    async def is_pkce_required(self, client_id, request):
        client = await self._client(client_id)
        return client is None or not client.is_confidential

    async def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        self.session.add(AuthorizationCode(
            code=code['code'],
            client_id=client_id,
            user=request.user,
            redirect_uri=request.redirect_uri,
            scopes=' '.join(request.scopes),
            code_challenge=request.code_challenge,
            code_challenge_method=request.code_challenge_method,
            expires_at=utcnow() + self.code_lifetime,
        ))

    # -- token request: authorization_code --------------------------------
    #
    # oauthlib calls validate_code() first, then get_code_challenge*(),
    # confirm_redirect_uri() and finally invalidate_authorization_code().
    # validate_code() *consumes* the code with an atomic DELETE ... RETURNING
    # and keeps the row on the request for the later calls. Of several
    # concurrent requests presenting the same code only one gets the row;
    # the others see no row and fail with invalid_grant. If validation fails
    # later on, the handler never commits and the code is restored by the
    # rollback.

    async def validate_code(self, client_id, code, client, request, *args, **kwargs):
        grant = await self.session.scalar(
            delete(AuthorizationCode)
            .where(AuthorizationCode.code == code,
                   AuthorizationCode.client_id == client_id,
                   AuthorizationCode.expires_at > utcnow())
            .returning(AuthorizationCode))
        if grant is None:
            return False
        request.authorization_code = grant
        request.user = grant.user
        request.scopes = grant.scopes.split()
        return True

    async def get_code_challenge(self, code, request):
        grant = getattr(request, 'authorization_code', None)
        return grant.code_challenge if grant else None

    async def get_code_challenge_method(self, code, request):
        grant = getattr(request, 'authorization_code', None)
        return grant.code_challenge_method if grant else None

    async def confirm_redirect_uri(self, client_id, code, redirect_uri, client, request, *args, **kwargs):
        grant = getattr(request, 'authorization_code', None)
        return grant is not None and grant.redirect_uri == redirect_uri

    async def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        return grant_type in ('authorization_code', 'refresh_token')

    async def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        pass  # already consumed atomically in validate_code()

    # -- token request: refresh_token ---------------------------------------
    #
    # Refresh token rotation: validate_refresh_token() consumes the old token
    # pair atomically (same reasoning as validate_code), so a refresh token
    # can be exchanged exactly once, even under concurrent requests.

    async def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        token = await self.session.scalar(
            delete(Token)
            .where(Token.refresh_token == refresh_token,
                   Token.client_id == client.client_id)
            .returning(Token))
        if token is None:
            return False
        request.previous_token = token
        request.user = token.user
        return True

    async def get_original_scopes(self, refresh_token, request, *args, **kwargs):
        token = getattr(request, 'previous_token', None)
        return token.scopes.split() if token else []

    # -- token persistence -------------------------------------------------

    async def save_bearer_token(self, token, request, *args, **kwargs):
        self.session.add(Token(
            access_token=token['access_token'],
            refresh_token=token.get('refresh_token'),
            client_id=request.client.client_id,
            user=request.user,
            scopes=token.get('scope', ' '.join(request.scopes or [])),
            expires_at=utcnow() + datetime.timedelta(seconds=token['expires_in']),
        ))

    # -- protected resources -----------------------------------------------

    async def validate_bearer_token(self, token, scopes, request):
        if not token:
            return False
        stored = await self.session.get(Token, token)
        if stored is None or stored.expires_at < utcnow():
            return False
        if not set(scopes or []) <= set(stored.scopes.split()):
            return False
        request.user = stored.user
        request.client_id = stored.client_id
        request.scopes = stored.scopes.split()
        return True


# --------------------------------------------------------------------------
# FastAPI wiring
# --------------------------------------------------------------------------

router = APIRouter()


def _serialize_sqlite_writes(engine: AsyncEngine):
    """SQLite only: open every transaction with BEGIN IMMEDIATE.

    pysqlite/aiosqlite start transactions lazily, which lets two concurrent
    transactions both read and then deadlock (``database is locked``) when
    they try to write. BEGIN IMMEDIATE takes the write lock up front so
    transactions queue instead. Not needed for PostgreSQL/MySQL, whose row
    locks already serialise the DELETE ... RETURNING above.
    """
    @event.listens_for(engine.sync_engine, 'connect')
    def _connect(dbapi_connection, connection_record):
        dbapi_connection.isolation_level = None  # let us issue BEGIN ourselves

    @event.listens_for(engine.sync_engine, 'begin')
    def _begin(conn):
        conn.exec_driver_sql('BEGIN IMMEDIATE')


async def _seed(sessionmaker):
    async with sessionmaker() as session, session.begin():
        if await session.get(Client, 'demo-client') is None:
            session.add(Client(
                client_id='demo-client', client_secret='demo-secret',
                redirect_uris='http://localhost:8080/callback',
                default_scopes='profile', allowed_scopes='profile email'))
            session.add(Client(
                client_id='demo-spa', client_secret=None,
                redirect_uris='http://localhost:3000/callback',
                default_scopes='profile', allowed_scopes='profile'))


def create_app(database_url: str = DATABASE_URL) -> FastAPI:
    engine = create_async_engine(database_url)
    if engine.dialect.name == 'sqlite':
        _serialize_sqlite_writes(engine)

    @asynccontextmanager
    async def lifespan(app):
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await _seed(app.state.sessionmaker)
        yield
        await engine.dispose()

    app = FastAPI(lifespan=lifespan)
    app.state.sessionmaker = async_sessionmaker(engine, expire_on_commit=False)
    app.include_router(router)
    return app


async def get_session(request: Request):
    async with request.app.state.sessionmaker() as session:
        yield session  # uncommitted work is rolled back on close


def get_server(session: AsyncSession = Depends(get_session)) -> WebApplicationServer:
    return WebApplicationServer(SQLAlchemyRequestValidator(session))


async def to_oauthlib(request: Request):
    """Starlette request -> oauthlib's (uri, http_method, body, headers)."""
    body = await request.body()
    return str(request.url), request.method, body.decode('utf-8') or None, dict(request.headers)


def to_response(headers, body, status):
    return Response(content=body or '', status_code=status, headers=headers)


def current_user(x_user: Optional[str] = Header(default=None)) -> str:
    """Stand-in for your real resource-owner authentication."""
    if not x_user:
        raise HTTPException(401, 'login required')
    return x_user


@router.get('/authorize')
async def authorize_prompt(request: Request, user: str = Depends(current_user),
                           server: WebApplicationServer = Depends(get_server)):
    """Validate the request and return what a consent screen would show."""
    uri, method, body, headers = await to_oauthlib(request)
    try:
        scopes, info = await server.validate_authorization_request(uri, method, body, headers)
    except FatalClientError as e:
        # Invalid client_id/redirect_uri: never redirect, show an error page.
        raise HTTPException(e.status_code, e.description) from e
    except OAuth2Error as e:
        return to_response({'Location': e.in_uri(e.redirect_uri)}, None, 302)
    return {'client_id': info['client_id'], 'scopes': scopes, 'user': user}


@router.post('/authorize')
async def authorize_confirm(request: Request, user: str = Depends(current_user),
                            session: AsyncSession = Depends(get_session)):
    """The user approved: issue the code (scopes come from the consent form)."""
    server = get_server(session)
    uri, _method, _body, headers = await to_oauthlib(request)
    form = await request.form()
    scopes = form.get('scope', '').split() or None
    try:
        headers, body, status = await server.create_authorization_response(
            uri, 'GET', None, headers, scopes=scopes, credentials={'user': user})
    except FatalClientError as e:
        raise HTTPException(e.status_code, e.description) from e
    await session.commit()
    return to_response(headers, body, status)


@router.post('/token')
async def token(request: Request, session: AsyncSession = Depends(get_session)):
    server = get_server(session)
    headers, body, status = await server.create_token_response(*await to_oauthlib(request))
    if status == 200:
        await session.commit()
    return to_response(headers, body, status)


def require_oauth(*scopes):
    """FastAPI dependency protecting a route with a bearer token."""
    async def dependency(request: Request, server: WebApplicationServer = Depends(get_server)):
        uri, method, body, headers = await to_oauthlib(request)
        valid, oauth_request = await server.verify_request(uri, method, body, headers, scopes=list(scopes))
        if not valid:
            raise HTTPException(401, 'invalid_token', headers={'WWW-Authenticate': 'Bearer'})
        return oauth_request
    return dependency


@router.get('/me')
async def me(oauth=Depends(require_oauth('profile'))):
    return {'user': oauth.user, 'client_id': oauth.client_id, 'scopes': oauth.scopes}


app = create_app()
