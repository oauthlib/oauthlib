# -*- coding: utf-8 -*-
"""
oauthlib.oauth2.rfc6749.grant_types.openid_connect
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
from __future__ import absolute_import, unicode_literals

import logging
import warnings

from oauthlib.openid.connect.core.grant_types.authorization_code import AuthorizationCodeGrant
from oauthlib.openid.connect.core.grant_types.base import GrantTypeBase
from oauthlib.openid.connect.core.grant_types.implicit import ImplicitGrant
from oauthlib.openid.connect.core.grant_types.hybrid import HybridGrant
from oauthlib.openid.connect.core.grant_types.dispatchers import (
    ImplicitTokenGrantDispatcher as NewImplicitTokenGrantDispatcher,
    AuthorizationTokenGrantDispatcher,
    AuthorizationCodeGrantDispatcher
)
from oauthlib.openid.connect.core.grant_types.exceptions import OIDCNoPrompt as NewOIDCNoPrompt

log = logging.getLogger(__name__)

warnings.warn(
    "Should not use this module! Use: "
    "oauthlib.openid.connect.core.grant_types.authorization_code.AuthorizationCodeGrant, "
    "oauthlib.openid.connect.core.grant_types.base.GrantTypeBase, "
    "oauthlib.openid.connect.core.grant_types.implicit.ImplicitGrant, "
    "oauthlib.openid.connect.core.grant_types.hybrid.HybridGrant, "
    "oauthlib.openid.connect.core.grant_types.dispatchers.ImplicitTokenGrantDispatcher, "
    "oauthlib.openid.connect.core.grant_types.dispatchers.AuthorizationTokenGrantDispatcher, "
    "oauthlib.openid.connect.core.grant_types.dispatchers.AuthorizationCodeGrantDispatcher, "
    "oauthlib.openid.connect.core.grant_types.exceptions.OIDCNoPrompt "
    "istead.",
    DeprecationWarning)


OIDCNoPrompt = NewOIDCNoPrompt
AuthCodeGrantDispatcher = AuthorizationCodeGrantDispatcher
ImplicitTokenGrantDispatcher = NewImplicitTokenGrantDispatcher
AuthTokenGrantDispatcher = AuthorizationTokenGrantDispatcher
OpenIDConnectBase = GrantTypeBase
OpenIDConnectAuthCode = AuthorizationCodeGrant
OpenIDConnectImplicit = ImplicitGrant
OpenIDConnectHybrid = HybridGrant
