# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

"""
oauthlib.oauth2
~~~~~~~~~~~~~~

This module is a wrapper for the most recent implementation of OAuth 2.0 Client
and Server classes.
"""

from .rfc6749 import Client, Server, WebApplicationClient
from .rfc6749 import UserAgentClient as MobileApplicationClient
from .rfc6749 import PasswordCredentialsClient as LegacyApplicationClient
from .rfc6749 import ClientCredentialsClient as BackendApplicationClient
from .rfc6749 import AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint
from .rfc6749 import WebApplicationServer, MobileApplicationServer
from .rfc6749 import LegacyApplicationServer, BackendApplicationServer
from .rfc6749.grant_types import *
from .rfc6749.tokens import BearerToken
from .rfc6749.errors import *
