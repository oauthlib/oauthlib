# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

"""
oauthlib.oauth2
~~~~~~~~~~~~~~

This module is a wrapper for the most recent implementation of OAuth 2.0 Client
and Server classes.
"""

from .draft25 import Client, Server, WebApplicationClient
from .draft25 import UserAgentClient as MobileApplicationClient
from .draft25 import PasswordCredentialsClient as LegacyApplicationClient
from .draft25 import ClientCredentialsClient as BackendApplicationClient
from .draft25 import AuthorizationEndpoint, TokenEndpoint, ResourceEndpoint
from .draft25 import WebApplicationServer, MobileApplicationServer
from .draft25 import LegacyApplicationServer, BackendApplicationServer
from .draft25.grant_types import *
from .draft25.tokens import BearerToken
from .draft25.errors import *
