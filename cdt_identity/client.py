import logging

from authlib.integrations.django_client import OAuth

from .models import IdentityGatewayConfig, ClaimsVerificationRequest

logger = logging.getLogger(__name__)

oauth = OAuth()


def _client_kwargs(extra_scopes: str = ""):
    """
    Generate the OpenID Connect client_kwargs, with optional extra scope(s).

    `extra_scopes` should be a space-separated list of scopes to add.
    """
    scopes = []
    if "openid" not in extra_scopes:
        scopes.append("openid")
    scopes.append(extra_scopes)
    return {"code_challenge_method": "S256", "scope": " ".join(scopes), "prompt": "login"}


def _server_metadata_url(authority):
    """
    Generate the OpenID Connect server_metadata_url for an OAuth authority server.

    `authority` should be a fully qualified HTTPS domain name, e.g. https://example.com.
    """
    return f"{authority}/.well-known/openid-configuration"


def _authorize_params(scheme):
    if scheme is not None:
        params = {"scheme": scheme}
    else:
        params = None

    return params


def create_client(oauth_registry: OAuth, config: IdentityGatewayConfig, request: ClaimsVerificationRequest):
    """
    Returns an OAuth client, registering first if needed.
    """
    client = oauth_registry.create_client(config.client_name)

    if client is None:
        # Register OAuth clients into the given registry, using the provided configuration.
        # Adapted from https://stackoverflow.com/a/64174413.
        logger.debug(f"Registering OAuth client: {config.client_name}")
        client = oauth_registry.register(
            config.client_name,
            client_id=str(config.client_id),
            server_metadata_url=_server_metadata_url(config.authority),
            client_kwargs=_client_kwargs(request.scopes),
            authorize_params=_authorize_params(request.scheme or config.scheme),
        )

    return client
