"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth 2 spec.
"""

import urllib
import urlparse


def scope_to_string(scope):
    """Convert a list of scopes to a space separated string."""
    if isinstance(scope, unicode) or scope is None:
        return scope
    elif isinstance(scope, list):
        return " ".join(scope)
    else:
        raise ValueError("Invalid scope, must be string or list.")


def scope_to_list(scope):
    """Convert a space separated string to a list of scopes."""
    if isinstance(scope, list) or scope is None:
        return scope
    else:
        return scope.split(" ")


def host_from_uri(uri):
    """Extract hostname and port from URI.

    Will use default port for HTTP and HTTPS if none is present in the URI.
    """
    default_ports = {
        u'HTTP': u'80',
        u'HTTPS': u'443',
    }

    sch, netloc, path, par, query, fra = urlparse.urlparse(uri)
    if u':' in netloc:
        netloc, port = netloc.split(u':', 1)
    else:
        port = default_ports.get(sch.upper())

    return netloc, port


def escape(u):
    """Escape a string in an OAuth-compatible fashion.

    TODO: verify whether this can in fact be used for OAuth 2

    """
    if not isinstance(u, unicode):
        raise ValueError('Only unicode objects are escapable.')
    return urllib.quote(u.encode('utf-8'), safe='~')


def valid_redirect_uri(uri):
    """Validate that the redirection endpoint URI is well formed.

    The redirection endpoint URI MUST be an absolute URI as defined by
    [RFC3986] section 4.3.  The endpoint URI MAY include an
    "application/x-www-form-urlencoded" formatted
    ([W3C.REC-html401-19991224]) query component ([RFC3986] section 3.4),
    which MUST be retained when adding additional query parameters.  The
    endpoint URI MUST NOT include a fragment component.

    .. `Section 3.1.2`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2

    """
    result = urlparse.urlparse(uri)
    if not result.scheme or result.fragment:
        return False
    return True


def normalize_uri(uri):
    """Normalize the URI according to rfc3986

    This currently just returns the same uri since there is no rfc3986
    compliant module which supports normalization.

    """
    return uri


def compare_uris(src, targets):
    """Compare the `src` URI to the URI's in the targets

    If multiple redirection URIs have been registered, if only part of
    the redirection URI has been registered, or if no redirection URI has
    been registered, the client MUST include a redirection URI with the
    authorization request using the "redirect_uri" request parameter.

    When a redirection URI is included in an authorization request, the
    authorization server MUST compare and match the value received
    against at least one of the registered redirection URIs (or URI
    components) as defined in [RFC3986] section 6, if any redirection
    URIs were registered.  If the client registration included the full
    redirection URI, the authorization server MUST compare the two URIs
    using simple string comparison as defined in [RFC3986] section 6.2.1.

    .. `Section 3.1.2.3`: http://tools.ietf.org/html/draft-ietf-oauth-v2-25#section-3.1.2.3

    TODO: Implement completely

    """
    parts = urlparse.urlsplit(normalize_uri(src))
    src = urlparse.urlunsplit(parts[:3] + (None,) + parts[4:])

    for uri in targets:
        if src == normalize_uri(uri):
            return True
    return False
