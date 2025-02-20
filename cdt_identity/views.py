import logging

from django.http import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse

from . import redirects
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
    redirect_uri = redirects.generate_redirect_uri(request, route)

    logger.debug(f"authorize_redirect with redirect_uri: {redirect_uri}")

    exception = None
    result = None

    try:
        result = oauth_client.authorize_redirect(request, redirect_uri)
    except Exception as ex:
        exception = ex

    if result and result.status_code >= 400:
        exception = Exception(f"authorize_redirect error response [{result.status_code}]: {result.content.decode()}")
    elif result is None and exception is None:
        exception = Exception("authorize_redirect returned None")

    if exception:
        raise exception

    return result


def logout(request: HttpRequest, hooks=DefaultHooks):
    """View handler for OIDC sign out with the CDT Identity Gateway."""
    logger.debug(Routes.route_logout)

    session = Session(request)
    oauth_client_result = _client_or_raise(request)

    if hasattr(oauth_client_result, "load_server_metadata"):
        # this looks like an oauth_client since it has the method we need
        # (called in redirects.deauthorize_redirect)
        oauth_client = oauth_client_result
    else:
        # this does not look like an oauth_client, it's an error redirect
        return oauth_client_result

    post_logout = Routes.route_post_logout
    if session.claims_request and session.claims_request.redirect_post_logout:
        post_logout = session.claims_request.redirect_post_logout

    post_logout_route = reverse(post_logout)
    post_logout_uri = redirects.generate_redirect_uri(request, post_logout_route)

    logger.debug(f"end_session_endpoint with redirect_uri: {post_logout_uri}")

    # send the user through the end_session_endpoint, redirecting back to
    # the post_logout URI
    return redirects.deauthorize_redirect(request, oauth_client, post_logout_uri)
