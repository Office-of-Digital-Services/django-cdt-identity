import logging

from django.http import HttpRequest
from django.shortcuts import redirect
from django.urls import reverse
from django.utils.http import urlencode

from .claims import ClaimsParser, ClaimsResult
from .client import create_client, oauth as registry
from .hooks import DefaultHooks, Operation
from .routes import Routes
from .session import Session

logger = logging.getLogger(__name__)


def _client_or_error(request: HttpRequest, hooks=DefaultHooks):
    """Calls `cdt_identity.client.create_client()`.

    If a client is created successfully, return it; otherwise, return a system error response.
    """
    client = None
    exception = None
    session = Session(request)

    config = session.client_config
    if not config:
        exception = Exception("No client config in session")

    if not exception:
        claims_request = session.claims_request
        client = create_client(registry, config, claims_request)
        if not client:
            exception = Exception(f"Client not registered: {config.client_name}")

    if exception:
        return hooks.system_error(request, exception, Operation.INIT)
    else:
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
    client_result = _client_or_error(request, hooks)

    if hasattr(client_result, "authorize_access_token"):
        # this looks like an oauth_client since it has the method we need
        oauth_client = client_result
    else:
        # this does not look like an oauth_client, it's an error redirect
        return client_result

    hooks.pre_authorize(request)
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
        return hooks.system_error(request, exception, Operation.AUTHORIZE_ACCESS_TOKEN)

    hooks.post_authorize(request)
    logger.debug("Access token authorized")

    claims_request = session.claims_request
    claims_result = ClaimsResult()
    hooks.pre_claims_verification(request, claims_request)

    # Process the returned claims
    if claims_request and claims_request.claims_list:
        userinfo = token.get("userinfo", {})
        claims_result = ClaimsParser.parse(userinfo, claims_request.claims_list)

    session.claims_result = claims_result

    # if we found the eligibility claim
    if claims_request and claims_request.eligibility_claim and claims_request.eligibility_claim in claims_result:
        return hooks.claims_verified_eligible(request, claims_request, claims_result)

    # else not eligible
    if claims_result.errors:
        logger.error(claims_result.errors)

    return hooks.claims_verified_not_eligible(request, claims_request, claims_result)


def cancel(request, hooks=DefaultHooks):
    """View implementing login cancellation."""
    logger.debug(Routes.route_cancel)

    return hooks.cancel_login(request)


def login(request: HttpRequest, hooks=DefaultHooks):
    """View implementing OIDC authorize_redirect with the CDT Identity Gateway."""
    logger.debug(Routes.route_login)

    client_result = _client_or_error(request, hooks)

    if hasattr(client_result, "authorize_redirect"):
        # this looks like an oauth_client since it has the method we need
        oauth_client = client_result
    else:
        # this does not look like an oauth_client, it's an error redirect
        return client_result

    hooks.pre_login(request)

    route = reverse(Routes.route_authorize)
    redirect_uri = _generate_redirect_uri(request, route)

    logger.debug(f"authorize_redirect with redirect_uri: {redirect_uri}")

    exception = None
    response = None

    try:
        response = oauth_client.authorize_redirect(request, redirect_uri)
    except Exception as ex:
        exception = ex

    if response and response.status_code >= 400:
        exception = Exception(f"authorize_redirect error response [{response.status_code}]: {response.content.decode()}")
    elif response is None and exception is None:
        exception = Exception("authorize_redirect returned None")

    if exception:
        return hooks.system_error(request, exception, Operation.AUTHORIZE_REDIRECT)

    hooks.post_login(request)

    return response


def logout(request: HttpRequest, hooks=DefaultHooks):
    """View handler for OIDC sign out with the CDT Identity Gateway."""
    logger.debug(Routes.route_logout)

    client_result = _client_or_error(request, hooks)

    if hasattr(client_result, "load_server_metadata"):
        # this looks like an oauth_client since it has the method we need
        oauth_client = client_result
    else:
        # this does not look like an oauth_client, it's an error redirect
        return client_result

    hooks.pre_logout(request)

    route = reverse(Routes.route_post_logout)
    post_logout_uri = _generate_redirect_uri(request, route)
    logger.debug(f"end_session_endpoint with redirect_uri: {post_logout_uri}")

    # Authlib has not yet implemented `end_session_endpoint` as the OIDC Session Management 1.0 spec is still in draft
    # See https://github.com/lepture/authlib/issues/331#issuecomment-827295954 for more
    #
    # The implementation here was adapted from the same ticket: https://github.com/lepture/authlib/issues/331#issue-838728145
    #
    # Send the user through the end_session_endpoint, redirecting back to the post_logout URI
    metadata = {}
    try:
        metadata = oauth_client.load_server_metadata()
    except Exception as exception:
        return hooks.system_error(request, exception, Operation.LOAD_SERVER_METADATA)

    end_session_endpoint = metadata.get("end_session_endpoint")
    params = dict(client_id=oauth_client.client_id, post_logout_redirect_uri=post_logout_uri)
    encoded_params = urlencode(params)
    end_session_url = f"{end_session_endpoint}?{encoded_params}"

    return redirect(end_session_url)


def post_logout(request: HttpRequest, hooks=DefaultHooks):
    """View implementing logout completion."""
    logger.debug(Routes.route_post_logout)

    return hooks.post_logout(request)
