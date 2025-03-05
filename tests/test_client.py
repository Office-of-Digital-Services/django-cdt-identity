from uuid import uuid4

import pytest

from cdt_identity.client import _authorize_params, _client_kwargs, _server_metadata_url, create_client
from cdt_identity.models import IdentityGatewayConfig, ClaimsVerificationRequest


def test_client_kwargs():
    kwargs = _client_kwargs()

    assert kwargs["code_challenge_method"] == "S256"
    assert kwargs["prompt"] == "login"
    assert "openid" in kwargs["scope"]


def test_client_kwargs_scope():
    kwargs = _client_kwargs("openid scope1")

    assert "openid" in kwargs["scope"]
    assert "scope1" in kwargs["scope"]


def test_server_metadata_url():
    url = _server_metadata_url("https://example.com")

    assert url.startswith("https://example.com")
    assert url.endswith("openid-configuration")


@pytest.mark.parametrize(
    "scheme,expected",
    [
        ("test_scheme", {"scheme": "test_scheme"}),
        (None, None),
    ],
)
def test_authorize_params(scheme, expected):
    params = _authorize_params(scheme)

    assert params == expected


@pytest.mark.django_db
def test_create_client_registered(mocker, mock_oauth_registry):
    mock_config = mocker.Mock(spec=IdentityGatewayConfig)
    mock_config.client_name = "client_name_1"
    mock_config.client_id = "client_id_1"

    create_client(mock_oauth_registry, mock_config, "scopes")

    mock_oauth_registry.create_client.assert_any_call("client_name_1")
    mock_oauth_registry.register.assert_not_called()


@pytest.mark.django_db
def test_create_client_not_registered(mocker, mock_oauth_registry):
    mock_client = mocker.Mock(spec=IdentityGatewayConfig)
    mock_client.client_name = "client_name_1"
    mock_client.client_id = uuid4()

    mock_request = mocker.Mock(spec=ClaimsVerificationRequest)

    mocker.patch("cdt_identity.client._client_kwargs", return_value={"client": "kwargs"})
    mocker.patch("cdt_identity.client._server_metadata_url", return_value="https://metadata.url")
    mocker.patch("cdt_identity.client._authorize_params", return_value={"scheme": "test_scheme"})

    mock_oauth_registry.create_client.return_value = None

    create_client(mock_oauth_registry, mock_client, mock_request)

    mock_oauth_registry.create_client.assert_any_call("client_name_1")
    mock_oauth_registry.register.assert_any_call(
        "client_name_1",
        client_id=str(mock_client.client_id),
        server_metadata_url="https://metadata.url",
        client_kwargs={"client": "kwargs"},
        authorize_params={"scheme": "test_scheme"},
    )
