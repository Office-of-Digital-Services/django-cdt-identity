import logging

from django.http import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import urlencode

from .claims import ClaimsParser
from .client import create_client, oauth as registry
from .hooks import DefaultHooks
from .routes import Routes
from .session import Session

logger = logging.getLogger(__name__)


def _client_or_raise(request: HttpRequest):
    """Calls `cdt_identity.client.create_client()`.

    If a client is created successfully, return it; otherwise, raise an appropriate Exception.
    """
    client = None
    session = Session(request)

    config = session.client_config
    if not config:
        raise Exception("No client config in session")

    claims_request = session.claims_request
    client = create_client(registry, config, claims_request)
    if not client:
        raise Exception(f"Client not registered: {config.client_name}")

    return client


def _generate_redirect_uri(request: HttpRequest, redirect_path: str):
    redirect_uri = str(request.build_absolute_uri(redirect_path)).lower()

    # this is a temporary hack to ensure redirect URIs are HTTPS when the app is deployed
    # see https://github.com/cal-itp/benefits/issues/442 for more context
    if not redirect_uri.startswith("http://localhost"):
        redirect_uri = redirect_uri.replace("http://", "https://")

    return redirect_uri


def authorize(request: HttpRequest, hooks=DefaultHooks):
    """View implementing OIDC token authorization with the CDT Identity Gateway."""
    logger.debug(Routes.route_authorize)

    session = Session(request)
    client_result = _client_or_raise(request)

    if hasattr(client_result, "authorize_access_token"):
        # this looks like an oauth_client since it has the method we need
        oauth_client = client_result
    else:
        # this does not look like an oauth_client, it's an error redirect
        return client_result

    logger.debug("Attempting to authorize access token")
    token = None
    exception = None

    try:
        token = oauth_client.authorize_access_token(request)
    except Exception as ex:
        exception = ex

    if token is None and not exception:
        logger.warning("Could not authorize access token")
        exception = Exception("authorize_access_token returned None")

    if exception:
        raise exception

    logger.debug("Access token authorized")

    # Process the returned claims
    if session.claims_request.all_claims:
        userinfo = token.get("userinfo", {})
        session.claims_result = ClaimsParser.parse(userinfo, session.claims_request.all_claims)

    # if we found the eligibility claim
    eligibility_claim = session.claims_request.eligibility_claim
    if eligibility_claim and eligibility_claim in session.claims_result:
        return redirect(session.claims_request.redirect_success)

    # else redirect to failure
    if session.claims_result and session.claims_result.errors:
        logger.error(session.claims_result.errors)

    return redirect(session.claims_request.redirect_fail)


def login(request: HttpRequest, hooks=DefaultHooks):
    """View implementing OIDC authorize_redirect with the CDT Identity Gateway."""
    logger.debug(Routes.route_login)

    oauth_client_result = _client_or_raise(request)

    if hasattr(oauth_client_result, "authorize_redirect"):
        # this looks like an oauth_client since it has the method we need
        oauth_client = oauth_client_result
    else:
        # this does not look like an oauth_client, it's an error redirect
        return oauth_client_result

    route = reverse(Routes.route_authorize)
    redirect_uri = _generate_redirect_uri(request, route)

    logger.debug(f"authorize_redirect with redirect_uri: {redirect_uri}")

    exception = None
    response = None

    try:
        hooks.pre_login(request)
        response = oauth_client.authorize_redirect(request, redirect_uri)
    except Exception as ex:
        exception = ex

    if response and response.status_code >= 400:
        exception = Exception(f"authorize_redirect error response [{response.status_code}]: {response.content.decode()}")
    elif response is None and exception is None:
        exception = Exception("authorize_redirect returned None")

    if exception:
        raise exception

    response = hooks.post_login(request, response)

    return response


def logout(request: HttpRequest, hooks=DefaultHooks):
    """View handler for OIDC sign out with the CDT Identity Gateway."""
    logger.debug(Routes.route_logout)

    session = Session(request)
    oauth_client_result = _client_or_raise(request)

    if hasattr(oauth_client_result, "load_server_metadata"):
        # this looks like an oauth_client since it has the method we need
        oauth_client = oauth_client_result
    else:
        # this does not look like an oauth_client, it's an error redirect
        return oauth_client_result

    route = Routes.route_post_logout
    if session.claims_request and session.claims_request.redirect_post_logout:
        route = session.claims_request.redirect_post_logout

    route = reverse(route)
    post_logout_uri = _generate_redirect_uri(request, route)

    logger.debug(f"end_session_endpoint with redirect_uri: {post_logout_uri}")

    # Authlib has not yet implemented `end_session_endpoint` as the OIDC Session Management 1.0 spec is still in draft
    # See https://github.com/lepture/authlib/issues/331#issuecomment-827295954 for more
    #
    # The implementation here was adapted from the same ticket: https://github.com/lepture/authlib/issues/331#issue-838728145
    #
    # Send the user through the end_session_endpoint, redirecting back to the post_logout URI
    metadata = oauth_client.load_server_metadata()
    end_session_endpoint = metadata.get("end_session_endpoint")

    params = dict(client_id=oauth_client.client_id, post_logout_redirect_uri=post_logout_uri)
    encoded_params = urlencode(params)
    end_session_url = f"{end_session_endpoint}?{encoded_params}"

    return redirect(end_session_url)
