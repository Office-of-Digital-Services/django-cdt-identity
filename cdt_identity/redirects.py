from authlib.integrations.base_client import OAuth2Mixin

from django.http import HttpRequest
from django.shortcuts import redirect
from django.utils.http import urlencode


def deauthorize_redirect(request: HttpRequest, oauth_client: OAuth2Mixin, redirect_uri: str):
    """Helper implements OIDC signout via the `end_session_endpoint`."""

    # Authlib has not yet implemented `end_session_endpoint` as the OIDC Session Management 1.0 spec is still in draft
    # See https://github.com/lepture/authlib/issues/331#issuecomment-827295954 for more
    #
    # The implementation here was adapted from the same ticket: https://github.com/lepture/authlib/issues/331#issue-838728145
    metadata = oauth_client.load_server_metadata()
    end_session_endpoint = metadata.get("end_session_endpoint")

    params = dict(client_id=oauth_client.client_id, post_logout_redirect_uri=redirect_uri)
    encoded_params = urlencode(params)
    end_session_url = f"{end_session_endpoint}?{encoded_params}"

    return redirect(end_session_url)


def generate_redirect_uri(request: HttpRequest, redirect_path: str):
    redirect_uri = str(request.build_absolute_uri(redirect_path)).lower()

    # this is a temporary hack to ensure redirect URIs are HTTPS when the app is deployed
    # see https://github.com/cal-itp/benefits/issues/442 for more context
    if not redirect_uri.startswith("http://localhost"):
        redirect_uri = redirect_uri.replace("http://", "https://")

    return redirect_uri
