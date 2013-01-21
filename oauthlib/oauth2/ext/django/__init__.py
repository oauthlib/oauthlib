from __future__ import unicode_literals
from django.http import HttpResponseRedirect, HttpResponse, HttpResponseForbidden
from django.views.decorators.csrf import csrf_exempt
import functools
from oauthlib.oauth2.draft25 import errors


class OAuth2ProviderDecorator(object):

    def __init__(self, server, error_uri):
        self._server = server
        self._error_uri = error_uri

    def pre_authorization_view(self, f):

        @functools.wraps(f)
        def wrapper(request, *args, **kwargs):
            uri = request.build_absolute_uri()
            http_method = request.method
            headers = request.META
            del headers['wsgi.input']
            body = ''.join(('%s=%s' % (k, v) for k, v in request.POST))
            redirect_uri = request.GET.get('redirect_uri', None)
            try:
                valid, scopes, credentials = self._server.validate_authorization_request(
                        uri, http_method, body, headers)
                if valid:
                    request.session['oauth2_credentials'] = credentials
                    kwargs['scopes'] = scopes
                    return f(request, *args, **kwargs)

            except errors.FatalClientError as e:
                return HttpResponseRedirect(e.in_uri(self._error_uri))

            except errors.OAuth2Error as e:
                return HttpResponseRedirect(e.in_uri(redirect_uri))
        return wrapper

    def post_authorization_view(self, f):
        @functools.wraps(f)
        def wrapper(request, *args, **kwargs):
            scopes = f(request, *args, **kwargs)
            uri = request.build_absolute_uri()
            http_method = request.method
            headers = request.META
            del headers['wsgi.input']
            body = request.POST
            credentials = request.session.get('oauth2_credentials', {})
            redirect_uri = credentials.get('redirect_uri')
            try:
                url, headers, body, status = self._server.create_authorization_response(
                        uri, http_method, body, headers, scopes, credentials)
                return HttpResponseRedirect(url)
            except errors.FatalClientError as e:
                return HttpResponseRedirect(e.in_uri(self._error_uri))
            except errors.OAuth2Error as e:
                return HttpResponseRedirect(e.in_uri(redirect_uri))

        return wrapper

    def access_token_view(self, f):
        @csrf_exempt
        @functools.wraps(f)
        def wrapper(request, *args, **kwargs):
            uri = request.build_absolute_uri()
            http_method = request.method
            headers = request.META
            del headers['wsgi.input']
            body = request.POST
            url, headers, body, status = self._server.create_token_response(
                    uri, http_method, body, headers)
            response = HttpResponse(content=body, status=status)
            for k, v in headers:
                response[k] = v
            return response
        return wrapper

    def protected_resource_view(self, scopes=None):
        def decorator(f):
            @csrf_exempt
            @functools.wraps(f)
            def wrapper(request, *args, **kwargs):
                uri = request.build_absolute_uri()
                http_method = request.method
                headers = request.META
                del headers['wsgi.input']
                body = request.POST
                valid, r = self._server.verify_request(uri, http_method, body, headers)
                kwargs.update({
                    'client_id': r.client_id,
                    'resource_owner': r.resource_owner,
                })
                if valid:
                    return f(request, *args, **kwargs)
                else:
                    return HttpResponseForbidden()
            return wrapper
        return decorator
