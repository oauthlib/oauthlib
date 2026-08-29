"""
oauthlib.openid.connect.core.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging

from oauthlib.oauth2.rfc8628.grant_types import (
    DeviceCodeGrant as OAuth2DeviceCodeGrant,
)

from .base import GrantTypeBase

log = logging.getLogger(__name__)


class DeviceCodeGrant(GrantTypeBase):

    def __init__(self, request_validator=None, **kwargs):
        self.proxy_target = OAuth2DeviceCodeGrant(
            request_validator=request_validator, **kwargs)
        self.register_token_modifier(self.add_id_token)

    def add_id_token(self, token, token_handler, request):
        """
        Device authorization has no response_type. Mint an id_token whenever
        the authorized scopes include openid.
        """
        if not request.scopes or "openid" not in request.scopes:
            return token
        # GrantTypeBase.add_id_token bails if response_type is set and does
        # not include id_token. Device code never uses that parameter.
        saved = getattr(request, "response_type", None)
        request.response_type = None
        try:
            return super().add_id_token(token, token_handler, request)
        finally:
            request.response_type = saved
