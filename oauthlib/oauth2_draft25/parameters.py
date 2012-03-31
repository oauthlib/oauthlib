from __future__ import absolute_import
"""
oauthlib.oauth2_draft25.parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This module contains methods related to `section 4`_ of the OAuth 2 draft.

.. _`section 4`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4
"""

try:
    import json
except ImportError:
    import simplejson as json

import urlparse
from . import utils

def prepare_grant_uri(uri, client_id, response_type, redirect_uri=None,
            scope=None, state=None, **kwargs):
    """Prepare the authorization grant request URI.

    Per `section 4.1.1`_ and `section 4.2.1`_ of the spec.

    .. _`section 4.1.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1.1
    .. _`section 4.2.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.2.1

    :param uri: Authorization endpoint URI.
    :param client_id: Client identifier given by service provider.
    :param response_type: u'code' or u'token' (implicit grant)
    :param redirect_uri: URI to redirect resource owner back to. 
    :param scope:  Resources access scope, i.e. "photos".
    :param state: Per request state.
    :param kwargs: Extra arguments to include in the URI.
    :returns: request uri with added OAuth parameters
    """
    
    params = [((u'response_type', response_type)),
              ((u'client_id', client_id))]

    if redirect_uri:
        params.append((u'redirect_uri', redirect_uri))
    if scope:
        params.append((u'scope', scope))
    if state:
        params.append((u'state', state))
    
    for k in kwargs:
        params.append((unicode(k), kwargs[k]))

    return utils.add_params_to_uri(uri, params)

def prepare_token_request(grant_type, body=u'', **kwargs):
    """Prepare the access token request.

    Common arguments for different client profiles (in addition to grant_type):

        Authorization code grant: 'code', 'redirect_uri'
        Resource owner password credentials grant: 'username', 'password', 'scope'
        Client credentials grant: 'scope'

    Per section `4.1.3`_, `4.3.2`_, `4.4.2`_ of the spec.

    .. _`4.1.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1.3
    .. _`4.3.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.3.2
    .. _`4.4.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.4.2

    :param grant_type: Usually one of u'code', u'password', u'client_credentials'
    :param body: Request body.
    :param kwargs: Extra arguments to include in the body.
    :return: request body with added OAuth 2 and extra parameters
    """
    params = [(u'grant_type', grant_type)]
    for k in kwargs:
        params.append((unicode(k), kwargs[k]))

    return utils.add_params_to_qs(body, params)

def parse_grant_uri(uri):
    """Parse authorization grant response URI into a dict.

    Per `section 4.1.2`_ of the spec.

    .. _`section 4.1.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1.2
    """
    params = urlparse.urlparse(uri).query
    return dict(urlparse.parse_qsl(params))

def validate_grant_params(params, state=None):
    """Ensure code precence and correct state in params. 
    Returns False if the redirection URI query is an `Error Response`_.
    
    Per `section 4.1.2`_ and `section 5.2`_ of the spec.

    .. _`section 4.1.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1.2
    .. _`Error Response`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.1.2.1
    """
    if u'error' in params:
        #raise ValueError("Error. Response was %s" % params)
        return False

    if state and params.get(u'state', None) != state:
        #raise ValueError("Mismatching or missing state in response, possible CSRF.")
        return False

    if not u'code' in params:
        #raise ValueError("Missing code parameter in response.")
        return False

    return True

def parse_token_uri(uri):
    """Parse the implicit token response URI into a dict.
    
    Per `section 4.2.2`_ of the spec.
    
    .. _`section 4.2.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.2.2
    """
    fragment = urlparse.urlparse(uri).fragment
    return dict(urlparse.parse_qsl(fragment, keep_blank_values=True))

def parse_token_body(body):
    """Parse the JSON token response body into a dict. 
    
    Per `section 5.1` of the spec.
    
    .. _`section 5.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-5.1
    """
    return json.loads(body)
    
def validate_token_params(params, state=None, scope=None):
    """Ensures token precence, token type, expiration and scope in params.
    Will also return False if params is a parsed error type per `section 5.2`_.

    Per `section 5.1` and `section 4.2.2`_ of the spec.

    .. _`section 5.1`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-5.1
    .. _`section 4.2.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-4.2.2
    .. _`section 5.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-5.2
    """
    if u'error' in params:
        #raise ValueError("Error. Response was %s" % params)
        return False

    if not u'access_token' in params:
        #raise ValueError("Missing access token parameter.")
        return False

    if not u'token_type' in params:
        #raise ValueError("Missing token type parameter.")
        return False

    # Implicit grant state check
    if state and params.get(u'state', None) != state:
        #raise ValueError("Mismatching or missing state in params, possible CSRF.")
        return False

    # Warn user if the token endpoint grants a different scope
    # http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.3
    new_scope = params.get(u'scope', None)
    if scope and new_scope and scope != new_scope:
        raise Warning("Scope has changed to %s." % new_scope)

    return True
