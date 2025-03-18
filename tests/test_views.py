import pytest
from django.http import HttpResponse
from unittest.mock import ANY

from cdt_identity.claims import ClaimsResult
from cdt_identity.hooks import DefaultHooks, Operation
from cdt_identity.routes import Routes
from cdt_identity.session import Session
from cdt_identity.views import _client_or_error, _generate_redirect_uri, authorize, cancel, login, logout, post_logout


@pytest.fixture
def mock_session(mocker):
    session = mocker.Mock(spec=Session)
    mocker.patch("cdt_identity.views.Session", return_value=session)
    return session


@pytest.fixture
def mock_create_client(mocker, mock_oauth_client):
    return mocker.patch("cdt_identity.views.create_client", return_value=mock_oauth_client)


@pytest.fixture
def mock_client_or_error(mocker, mock_oauth_client):
    return mocker.patch("cdt_identity.views._client_or_error", return_value=mock_oauth_client)


@pytest.fixture
def mock_hooks(mocker):
    return mocker.MagicMock(spec=DefaultHooks)


@pytest.fixture
def mock_redirect(mocker):
    return mocker.patch("cdt_identity.views.redirect")


@pytest.mark.django_db
def test_client_or_error_no_config(mocker, mock_request, mock_create_client):
    spy = mocker.spy(DefaultHooks, "system_error")
    response = _client_or_error(mock_request)

    mock_create_client.assert_not_called()
    spy.assert_called_once_with(ANY, ANY, Operation.INIT)
    assert response.status_code == 500
    assert response.content.decode() == "A system error occurred."


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_session")
def test_client_or_error_no_client(mocker, mock_create_client, mock_request):
    spy = mocker.spy(DefaultHooks, "system_error")
    mock_create_client.return_value = None

    response = _client_or_error(mock_request)

    spy.assert_called_once_with(ANY, ANY, Operation.INIT)
    assert response.status_code == 500
    assert response.content.decode() == "A system error occurred."


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_create_client", "mock_session")
def test_client_or_error_client(mock_request):
    result = _client_or_error(mock_request)

    assert hasattr(result, "authorize_redirect")


@pytest.mark.django_db
def test_generate_redirect_uri_default(mock_request):
    path = "/test"

    redirect_uri = _generate_redirect_uri(mock_request, path)

    assert redirect_uri == "https://testserver/test"


def test_generate_redirect_uri_localhost(rf, settings):
    settings.ALLOWED_HOSTS.append("localhost")
    request = rf.get("/oauth/login", SERVER_NAME="localhost")
    path = "/test"

    redirect_uri = _generate_redirect_uri(request, path)

    assert redirect_uri == "http://localhost/test"


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
def test_authorize_eligible(mocker, mock_oauth_client, mock_request, mock_session, mock_hooks):
    # build the mock response from authorize_access_token
    mock_oauth_client.authorize_access_token.return_value = {
        "id_token": "test_token",
        "userinfo": {"claim1": "1", "claim2": "value", "claim3": "value"},
    }

    claims_request = mocker.Mock(claims_list=["claim1", "claim2"], eligibility_claim="claim1")
    mock_session.claims_request = claims_request
    expected_result = ClaimsResult(verified={"claim1": True, "claim2": "value"})

    response = authorize(mock_request, mock_hooks)

    assert mock_session.claims_result == expected_result
    mock_hooks.pre_authorize.assert_called_once_with(mock_request)
    mock_hooks.post_authorize.assert_called_once_with(mock_request)
    mock_hooks.pre_claims_verification.assert_called_once_with(mock_request, claims_request)
    mock_hooks.claims_verified_eligible.assert_called_once_with(mock_request, claims_request, expected_result)
    assert response == mock_hooks.claims_verified_eligible.return_value


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
@pytest.mark.parametrize(
    "claims_list,eligibility_claim,userinfo,claims_result",
    [
        ([], None, {"claim1": "1", "claim2": "value", "claim3": "value"}, ClaimsResult()),
        (["claim4"], "claim4", {"claim1": "1", "claim2": "value", "claim3": "value"}, ClaimsResult()),
        (["claim1", "claim2"], "claim1", {}, ClaimsResult()),
        (["claim1", "claim2"], "claim1", {"claim1": 5, "claim2": 10, "claim3": 100}, ClaimsResult(errors={"claim2": 10})),
    ],
)
def test_authorize_not_eligible(
    mocker, mock_oauth_client, mock_request, mock_session, mock_hooks, claims_list, eligibility_claim, userinfo, claims_result
):
    # build the mock ClaimsVerificationRequest
    claims_request = mocker.Mock(claims_list=claims_list)
    if eligibility_claim:
        claims_request.eligibility_claim = eligibility_claim
    mock_session.claims_request = claims_request
    # build the mock response from authorize_access_token
    mock_oauth_client.authorize_access_token.return_value = {
        "id_token": "test_token",
        "userinfo": userinfo,
    }

    # call the test function
    response = authorize(mock_request, mock_hooks)

    # claims_result should be set
    assert mock_session.claims_result == claims_result
    # result from not eligible hook
    mock_hooks.claims_verified_not_eligible.assert_called_once_with(mock_request, claims_request, claims_result)
    assert response == mock_hooks.claims_verified_not_eligible.return_value


@pytest.mark.django_db
def test_authorize_no_client(mock_client_or_error, mock_request, mock_hooks):
    mock_client_or_error.return_value = "No client here"

    response = authorize(mock_request, mock_hooks)

    assert response == "No client here"


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
def test_authorize_no_token(mock_oauth_client, mock_request, mock_hooks):
    mock_oauth_client.authorize_access_token.return_value = None

    response = authorize(mock_request, mock_hooks)

    assert response == mock_hooks.system_error.return_value
    mock_hooks.system_error.assert_called_once_with(ANY, ANY, Operation.AUTHORIZE_ACCESS_TOKEN)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
def test_authorize_token_exception(mock_oauth_client, mock_request, mock_hooks):
    exception = Exception("authorize token failed")
    mock_oauth_client.authorize_access_token.side_effect = exception

    response = authorize(mock_request, mock_hooks)

    mock_hooks.system_error.assert_called_once_with(mock_request, exception, Operation.AUTHORIZE_ACCESS_TOKEN)
    assert response == mock_hooks.system_error.return_value


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_session")
def test_cancel(mock_request, mock_hooks):
    response = cancel(mock_request, mock_hooks)

    mock_hooks.cancel_login.assert_called_once_with(mock_request)
    assert response == mock_hooks.cancel_login.return_value


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
def test_login_success(mocker, mock_oauth_client, mock_request, mock_hooks):
    mock_oauth_client.authorize_redirect.return_value = HttpResponse(status=200)
    mock_reverse = mocker.patch("cdt_identity.views.reverse", return_value="authorize")

    response = login(mock_request, mock_hooks)

    assert response.status_code == 200
    mock_reverse.assert_called_once_with(Routes.route_authorize)
    mock_hooks.pre_login.assert_called_once_with(mock_request)
    mock_hooks.post_login.assert_called_once_with(mock_request)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
def test_login_failure(mock_oauth_client, mock_request, mock_hooks):
    mock_oauth_client.authorize_redirect.return_value = None

    login(mock_request, mock_hooks)

    mock_hooks.pre_login.assert_called_once_with(mock_request)
    mock_hooks.system_error.assert_called_once_with(ANY, ANY, Operation.AUTHORIZE_REDIRECT)
    mock_hooks.post_login.assert_not_called()


@pytest.mark.django_db
def test_login_no_client(mocker, mock_client_or_error, mock_request):
    error_redirect = mocker.Mock(spec=[])
    mock_client_or_error.return_value = error_redirect

    response = login(mock_request)

    assert response == error_redirect


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
def test_login_authorize_redirect_exception(mock_oauth_client, mock_request, mock_hooks):
    exception = Exception("authorize_redirect")
    mock_oauth_client.authorize_redirect.side_effect = exception

    login(mock_request, mock_hooks)

    mock_hooks.pre_login.assert_called_once_with(mock_request)
    mock_hooks.system_error.assert_called_once_with(mock_request, exception, Operation.AUTHORIZE_REDIRECT)
    mock_hooks.post_login.assert_not_called()


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
@pytest.mark.parametrize(
    "status_code, content",
    [
        (400, "bad request"),
        (404, "not found"),
        (500, "server error"),
    ],
)
def test_login_authorize_redirect_error_response(mock_oauth_client, mock_request, mock_hooks, status_code, content):
    mock_oauth_client.authorize_redirect.return_value = HttpResponse(content=content, status=status_code)

    login(mock_request, mock_hooks)

    mock_hooks.pre_login.assert_called_once_with(mock_request)
    mock_hooks.system_error.assert_called_once_with(ANY, ANY, Operation.AUTHORIZE_REDIRECT)
    mock_hooks.post_login.assert_not_called()


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
def test_logout(mocker, mock_oauth_client, mock_request, mock_redirect):
    mock_oauth_client.client_id = "test-client-id"
    mock_oauth_client.load_server_metadata.return_value = {"end_session_endpoint": "https://server/endsession"}
    mock_reverse = mocker.patch("cdt_identity.views.reverse", return_value="/logged-out")

    logout(mock_request)

    mock_reverse.assert_called_once_with("cdt:post_logout")
    mock_redirect.assert_called_once_with(
        "https://server/endsession?client_id=test-client-id&post_logout_redirect_uri=https%3A%2F%2Ftestserver%2Flogged-out"
    )


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
def test_logout_hooks(mock_oauth_client, mock_request, mock_hooks):
    mock_oauth_client.client_id = "test-client-id"
    mock_oauth_client.load_server_metadata.return_value = {"end_session_endpoint": "https://server/endsession"}

    logout(mock_request, mock_hooks)

    mock_hooks.pre_logout.assert_called_once_with(mock_request)


@pytest.mark.django_db
def test_logout_no_client(mocker, mock_client_or_error, mock_request):
    error_redirect = mocker.Mock(spec=[])
    mock_client_or_error.return_value = error_redirect

    response = logout(mock_request)

    assert response == error_redirect


@pytest.mark.django_db
def test_logout_default_redirect(mocker, mock_client_or_error, mock_request, mock_session):
    mock_session.claims_request = None
    error_redirect = mocker.Mock(spec=[])
    mock_client_or_error.return_value = error_redirect

    response = logout(mock_request)

    assert response == error_redirect


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_error")
def test_logout_load_server_metadata_exception(mock_request, mock_oauth_client, mock_hooks):
    mock_oauth_client.client_id = "test-client-id"
    exception = Exception("metadata")
    mock_oauth_client.load_server_metadata.side_effect = exception

    logout(mock_request, mock_hooks)

    mock_hooks.system_error.assert_called_once_with(mock_request, exception, Operation.LOAD_SERVER_METADATA)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_session")
def test_post_logout(mock_request, mock_hooks):
    response = post_logout(mock_request, mock_hooks)

    mock_hooks.post_logout.assert_called_once_with(mock_request)
    assert response == mock_hooks.post_logout.return_value
