# -*- coding: utf-8 -*-
"""
oauthlib.oauth2
~~~~~~~~~~~~~~

This module is a wrapper for the most recent implementation of OAuth 2.0 Client
and Server classes.
"""
from __future__ import absolute_import, unicode_literals

from .common.endpoints import AuthorizationEndpoint
from .common.endpoints import IntrospectEndpoint
from .common.endpoints import MetadataEndpoint
from .common.endpoints import TokenEndpoint
from .common.endpoints import ResourceEndpoint
from .common.endpoints import RevocationEndpoint
from .common.endpoints import Server
from .common.endpoints import WebApplicationServer
from .common.endpoints import MobileApplicationServer
from .common.endpoints import LegacyApplicationServer
from .common.endpoints import BackendApplicationServer

from .draft_ietf13.grant_types import DeviceCodeGrant
from .draft_ietf13.tokens import DeviceToken
from .draft_ietf13.request_validator import RequestValidator as DeviceCodeRequestValidator

from .rfc6749.clients import Client
from .rfc6749.clients import WebApplicationClient
from .rfc6749.clients import MobileApplicationClient
from .rfc6749.clients import LegacyApplicationClient
from .rfc6749.clients import BackendApplicationClient
from .rfc6749.clients import ServiceApplicationClient
from .rfc6749.errors import AccessDeniedError, OAuth2Error, FatalClientError, InsecureTransportError, InvalidClientError, InvalidClientIdError, InvalidGrantError, InvalidRedirectURIError, InvalidRequestError, InvalidRequestFatalError, InvalidScopeError, MismatchingRedirectURIError, MismatchingStateError, MissingClientIdError, MissingCodeError, MissingRedirectURIError, MissingResponseTypeError, MissingTokenError, MissingTokenTypeError, ServerError, TemporarilyUnavailableError, TokenExpiredError, UnauthorizedClientError, UnsupportedGrantTypeError, UnsupportedResponseTypeError, UnsupportedTokenTypeError
from .rfc6749.grant_types import AuthorizationCodeGrant
from .rfc6749.grant_types import ImplicitGrant
from .rfc6749.grant_types import ResourceOwnerPasswordCredentialsGrant
from .rfc6749.grant_types import ClientCredentialsGrant
from .rfc6749.grant_types import RefreshTokenGrant
from .rfc6749.request_validator import RequestValidator
from .rfc6749.tokens import BearerToken, OAuth2Token
from .rfc6749.utils import is_secure_transport
