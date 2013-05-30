# -*- coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals

"""
oauthlib.oauth2.rfc6749
~~~~~~~~~~~~~~~~~~~~~~~

This module is an implementation of various logic needed
for consuming and providing OAuth 2.0 RFC6749.
"""

from .authorization import AuthorizationEndpoint
from .token import TokenEndpoint
from .resource import ResourceEndpoint
from .pre_configured import Server
from .pre_configured import WebApplicationServer
from .pre_configured import MobileApplicationServer
from .pre_configured import LegacyApplicationServer
from .pre_configured import BackendApplicationServer
