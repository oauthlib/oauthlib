from .exceptions import MissingRedirectURI, InvalidRedirectURI
from .utils import valid_redirect_uri, compare_uris


class AuthorizationServer(object):
    def client_redirect_uris(self, client_identifier):
        raise NotImplementedError("Must be implemented by inheriting classes.")

    def redirect_uri(self, client_identifier, redirect_uri=None):
        redirect_uris = self.client_redirect_uris(client_identifier)

        # If multiple redirection URIs have been registered, if only part of
        # the redirection URI has been registered, or if no redirection URI has
        # been registered, the client MUST include a redirection URI.
        if not redirect_uri and len(redirect_uris) != 1:
            raise MissingRedirectURI()

        # If an redirect_uri is given then check that it is valid and is one
        # of the optionally URI's returned by `client_redirect_uris`.
        if redirect_uri:
            if not valid_redirect_uri(redirect_uri):
                raise InvalidRedirectURI()
            if redirect_uris:
                if not compare_uris(redirect_uri, redirect_uris):
                    raise InvalidRedirectURI()

            return redirect_uri
        return redirect_uris[0]
