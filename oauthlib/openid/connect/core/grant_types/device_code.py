"""
oauthlib.openid.connect.core.grant_types
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging

from oauthlib.oauth2.rfc8628.grant_types.device_code import (
    DeviceCodeGrant as OAuth2DeviceCodeGrant,
)

from .base import GrantTypeBase

log = logging.getLogger(__name__)


class DeviceCodeGrant(GrantTypeBase):

    def __init__(self, request_validator=None, **kwargs):
        self.proxy_target = OAuth2DeviceCodeGrant(
            request_validator=request_validator, **kwargs)
        self.register_token_modifier(self.add_id_token)
