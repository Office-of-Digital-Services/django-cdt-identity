import pytest

from cdt_identity.redirects import deauthorize_redirect, generate_redirect_uri


@pytest.mark.django_db
def test_deauthorize_redirect(mock_oauth_client, mock_request):
    mock_oauth_client.client_id = "test-client-id"
    mock_oauth_client.load_server_metadata.return_value = {"end_session_endpoint": "https://server/endsession"}

    result = deauthorize_redirect(mock_request, mock_oauth_client, "https://localhost/redirect_uri")

    mock_oauth_client.load_server_metadata.assert_called()
    assert result.status_code == 302
    assert (
        result.url
        == "https://server/endsession?client_id=test-client-id&post_logout_redirect_uri=https%3A%2F%2Flocalhost%2Fredirect_uri"
    )


@pytest.mark.django_db
def test_deauthorize_redirect_load_server_metadata_error(mock_oauth_client, mock_request):
    mock_oauth_client.load_server_metadata.side_effect = Exception("Side effect")

    with pytest.raises(Exception):
        deauthorize_redirect(mock_request, mock_oauth_client, "https://localhost/redirect_uri")


@pytest.mark.django_db
def test_generate_redirect_uri_default(mock_request):
    path = "/test"

    redirect_uri = generate_redirect_uri(mock_request, path)

    assert redirect_uri == "https://testserver/test"


def test_generate_redirect_uri_localhost(rf, settings):
    settings.ALLOWED_HOSTS.append("localhost")
    request = rf.get("/oauth/login", SERVER_NAME="localhost")
    path = "/test"

    redirect_uri = generate_redirect_uri(request, path)

    assert redirect_uri == "http://localhost/test"
