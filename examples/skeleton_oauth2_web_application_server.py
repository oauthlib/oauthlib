# Skeleton for an OAuth 2 Web Application Server which is an OAuth
# provider configured for Authorization Code, Refresh Token grants and
# for dispensing Bearer Tokens.

# This example is tailored for django but should translate to other
# web frameworks easily.

# This example is meant to act as a supplement to the documentation,
# see http://oauthlib.readthedocs.org/en/latest/.

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from oauthlib.oauth2 import RequestValidator, WebApplicationServer
from oauthlib.oauth2.ext.django import OAuth2ProviderDecorator


class SkeletonValidator(RequestValidator):

    # Ordered roughly in order of appearance in the authorization grant flow

    # Pre- and post-authorization.

    def validate_client_id(self, client_id, request, *args, **kwargs):
        # Simple validity check, does client exist? Not banned?
        pass

    def validate_redirect_uri(self, client_id, redirect_uri, request, *args, **kwargs):
        # Is the client allowed to use the supplied redirect_uri? i.e. has
        # the client previously registered this EXACT redirect uri.
        pass

    def get_default_redirect_uri(self, client_id, request, *args, **kwargs):
        # The redirect used if none has been supplied.
        # Prefer your clients to pre register a redirect uri rather than
        # supplying one on each authorization request.
        pass

    def validate_scopes(self, client_id, scopes, client, request, *args, **kwargs):
        # Is the client allowed to access the requested scopes?
        pass

    def get_default_scopes(self, client_id, request, *args, **kwargs):
        # Scopes a client will authorize for if none are supplied in the
        # authorization request.
        pass

    def validate_response_type(self, client_id, response_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of response type, the
        # one associated with their one allowed grant type.
        # In this case it must be "code".
        pass

    # Post-authorization

    def save_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.redirect_uri
        # request.client, request.state and request.user (the last is passed in
        # post_authorization credentials, i.e. { 'user': request.user}.
        pass

    # Token request

    def authenticate_client(self, request, *args, **kwargs):
        # Whichever authentication method suits you, HTTP Basic might work
        pass

    def authenticate_client_id(self, client_id, request, *args, **kwargs):
        # Don't allow public (non-authenticated) clients
        return False

    def validate_code(self, client_id, code, client, request, *args, **kwargs):
        # Validate the code belongs to the client. Add associated scopes,
        # state and user to request.scopes, request.state and request.user.
        pass

    def confirm_redirect_uri(self, client_id, code, redirect_uri, client, *args, **kwargs):
        # You did save the redirect uri with the authorization code right?
        pass

    def validate_grant_type(self, client_id, grant_type, client, request, *args, **kwargs):
        # Clients should only be allowed to use one type of grant.
        # In this case, it must be "authorization_code" or "refresh_token"
        pass

    def save_bearer_token(self, token, request, *args, **kwargs):
        # Remember to associate it with request.scopes, request.user and
        # request.client. The two former will be set when you validate
        # the authorization code. Don't forget to save both the
        # access_token and the refresh_token and set expiration for the
        # access_token to now + expires_in seconds.
        pass

    def invalidate_authorization_code(self, client_id, code, request, *args, **kwargs):
        # Authorization codes are use once, invalidate it when a Bearer token
        # has been acquired.
        pass

    # Protected resource request

    def validate_bearer_token(self, token, scopes, request):
        # Remember to check expiration and scope membership
        pass

    # Token refresh request

    def confirm_scopes(self, refresh_token, scopes, request, *args, **kwargs):
        # If the client requests a set of scopes, assure that those are the
        # same as, or a subset of, the ones associated with the token earlier.
        pass


validator = SkeletonValidator()
server = WebApplicationServer(validator)
provider = OAuth2ProviderDecorator('/error', server)


@login_required
@provider.pre_authorization_view
def authorize(request, scopes=None, client_id=None):
    # The user might not want to provide access to all scopes,
    # make it easy for them to opt-out.
    response = HttpResponse()
    response.write('<h1> Authorize access to %s </h1>' % client_id)
    response.write('<form method="POST" action="/post_authorization">')
    for scope in scopes or []:
        response.write('<input type="checkbox" name="scopes" value="%s"/> %s' % (scope, scope))
    response.write('<input type="submit" value="Authorize"/>')
    return response


@login_required
@provider.post_authorization_view
def authorization_response(request):
    # Only return scopes the user actually authorized, i.e. the checked
    # scope checkboxes from the authorize view.
    return request.POST['scopes'], {'user': request.user}


@provider.access_token_view
def token_response(request):
    # This dict will be available as request.extra_credentials in all
    # validation methods, including save_bearer_token.
    return {}


def error(request):
    return HttpResponse('Bad client! Warn user!')
