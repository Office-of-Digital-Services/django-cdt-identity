import re

import pytest
from django.http import HttpResponse

from cdt_identity.claims import ClaimsResult
from cdt_identity.routes import Routes
from cdt_identity.session import Session
from cdt_identity.views import _client_or_raise, authorize, login, logout


@pytest.fixture
def mock_session(mocker):
    session = mocker.Mock(spec=Session)
    mocker.patch("cdt_identity.views.Session", return_value=session)
    return session


@pytest.fixture
def mock_create_client(mocker, mock_oauth_client):
    return mocker.patch("cdt_identity.views.create_client", return_value=mock_oauth_client)


@pytest.fixture
def mock_client_or_raise(mocker, mock_oauth_client):
    return mocker.patch("cdt_identity.views._client_or_raise", return_value=mock_oauth_client)


@pytest.mark.django_db
def test_client_or_raise_no_config(mock_request, mock_create_client):
    with pytest.raises(Exception, match="No client config in session"):
        _client_or_raise(mock_request)

    mock_create_client.assert_not_called()


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_session")
def test_client_or_raise_no_client(mock_create_client, mock_request):
    mock_create_client.return_value = None

    with pytest.raises(Exception, match="Client not registered"):
        _client_or_raise(mock_request)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_create_client", "mock_session")
def test_client_or_raise_client(mock_request):
    result = _client_or_raise(mock_request)

    assert hasattr(result, "authorize_redirect")


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_authorize_success(mocker, mock_oauth_client, mock_request, mock_session):
    mock_oauth_client.authorize_access_token.return_value = {
        "id_token": "test_token",
        "userinfo": {"claim1": "1", "claim2": "value", "claim3": "value"},
    }
    mock_session.claims_request = mocker.Mock(
        all_claims=["claim1", "claim2"], eligibility_claim="claim1", redirect_success="/success"
    )
    mock_redirect = mocker.patch("cdt_identity.views.redirect")

    authorize(mock_request)

    mock_redirect.assert_called_once_with("/success")
    assert mock_session.claims_result == ClaimsResult(verified={"claim1": True, "claim2": "value"})


@pytest.mark.django_db
def test_authorize_no_client(mocker, mock_client_or_raise, mock_request):
    error_redirect = mocker.Mock(spec=[])
    mock_client_or_raise.return_value = error_redirect

    response = authorize(mock_request)

    assert response == error_redirect


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_authorize_no_token(mock_oauth_client, mock_request):
    mock_oauth_client.authorize_access_token.return_value = None

    with pytest.raises(Exception, match="authorize_access_token returned None"):
        authorize(mock_request)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_authorize_token_exception(mock_oauth_client, mock_request):
    mock_oauth_client.authorize_access_token.side_effect = Exception("authorize token failed")

    with pytest.raises(Exception, match="authorize token failed"):
        authorize(mock_request)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_authorize_no_claims(mocker, mock_oauth_client, mock_request, mock_session):
    mock_oauth_client.authorize_access_token.return_value = {
        "id_token": "test_token",
        "userinfo": {"claim1": "1", "claim2": "value", "claim3": "value"},
    }
    mock_session.claims_request = mocker.Mock(all_claims=[], redirect_fail="/fail")
    # we can mock this result because it is the default for a real session
    # since we have a Mock instance, we need to apply the default directly
    mock_session.claims_result = ClaimsResult()
    mock_redirect = mocker.patch("cdt_identity.views.redirect")

    authorize(mock_request)

    mock_redirect.assert_called_once_with("/fail")


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_authorize_no_extra_claims(mocker, mock_oauth_client, mock_request, mock_session):
    mock_oauth_client.authorize_access_token.return_value = {
        "id_token": "test_token",
        "userinfo": {"claim1": "1", "claim2": "value", "claim3": "value"},
    }
    mock_session.claims_request = mocker.Mock(all_claims=["claim4"], eligibility_claim="claim4", redirect_fail="/fail")
    mock_redirect = mocker.patch("cdt_identity.views.redirect")

    authorize(mock_request)

    mock_redirect.assert_called_once_with("/fail")
    assert mock_session.claims_result == ClaimsResult()


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_authorize_no_token_claims(mocker, mock_oauth_client, mock_request, mock_session):
    mock_oauth_client.authorize_access_token.return_value = {
        "id_token": "test_token",
        "userinfo": {},
    }
    mock_session.claims_request = mocker.Mock(
        all_claims=["claim1", "claim2"], eligibility_claim="claim1", redirect_fail="/fail"
    )
    mock_redirect = mocker.patch("cdt_identity.views.redirect")

    authorize(mock_request)

    mock_redirect.assert_called_once_with("/fail")
    assert mock_session.claims_result == ClaimsResult()


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_authorize_token_error_claims(mocker, mock_oauth_client, mock_request, mock_session):
    mock_oauth_client.authorize_access_token.return_value = {
        "id_token": "test_token",
        "userinfo": {"claim1": 5, "claim2": 10, "claim3": 100},
    }
    mock_session.claims_request = mocker.Mock(
        all_claims=["claim1", "claim2"], eligibility_claim="claim1", redirect_fail="/fail"
    )
    mock_redirect = mocker.patch("cdt_identity.views.redirect")

    authorize(mock_request)

    mock_redirect.assert_called_once_with("/fail")
    assert mock_session.claims_result == ClaimsResult(errors={"claim2": 10})


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_login_success(mocker, mock_oauth_client, mock_request):
    mock_oauth_client.authorize_redirect.return_value = HttpResponse(status=200)
    mock_reverse = mocker.patch("cdt_identity.views.reverse", return_value="authorize")

    response = login(mock_request)

    assert response.status_code == 200
    mock_reverse.assert_called_once_with(Routes.route_authorize)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_login_failure(mock_oauth_client, mock_request):
    mock_oauth_client.authorize_redirect.return_value = None

    with pytest.raises(Exception):
        login(mock_request)


@pytest.mark.django_db
def test_login_no_client(mocker, mock_client_or_raise, mock_request):
    error_redirect = mocker.Mock(spec=[])
    mock_client_or_raise.return_value = error_redirect

    response = login(mock_request)

    assert response == error_redirect


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_login_authorize_redirect_exception(mock_oauth_client, mock_request):
    mock_oauth_client.authorize_redirect.side_effect = Exception("authorize_redirect")

    with pytest.raises(Exception, match="authorize_redirect"):
        login(mock_request)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
@pytest.mark.parametrize(
    "status_code, content",
    [
        (400, "bad request"),
        (404, "not found"),
        (500, "server error"),
    ],
)
def test_login_authorize_redirect_error_response(mock_oauth_client, mock_request, status_code, content):
    mock_oauth_client.authorize_redirect.return_value = HttpResponse(content=content, status=status_code)

    with pytest.raises(Exception, match=re.escape(f"authorize_redirect error response [{status_code}]: {content}")):
        login(mock_request)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
# the "/post_logout" case represents a consuming app's customization of this route
# the None case represents this app's default
@pytest.mark.parametrize("post_logout_redirect", ("/post_logout", None))
def test_logout(mocker, mock_request, mock_session, post_logout_redirect):
    mock_redirects = mocker.patch("cdt_identity.views.redirects")
    mock_redirects.deauthorize_redirect.return_value = HttpResponse(status=200)
    mock_session.claims_request.redirect_post_logout = post_logout_redirect
    mock_reverse = mocker.patch("cdt_identity.views.reverse", return_value="deauthorize")

    response = logout(mock_request)

    assert response.status_code == 200
    mock_redirects.deauthorize_redirect.assert_called_once()
    if post_logout_redirect:
        mock_reverse.assert_called_once_with(post_logout_redirect)
    else:
        mock_reverse.assert_called_once_with(Routes.route_post_logout)


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_logout_no_client(mocker, mock_client_or_raise, mock_request):
    error_redirect = mocker.Mock(spec=[])
    mock_client_or_raise.return_value = error_redirect

    response = logout(mock_request)

    assert response == error_redirect


@pytest.mark.django_db
@pytest.mark.usefixtures("mock_client_or_raise")
def test_logout_default_redirect(mocker, mock_client_or_raise, mock_request, mock_session):
    mock_session.claims_request = None
    error_redirect = mocker.Mock(spec=[])
    mock_client_or_raise.return_value = error_redirect

    response = logout(mock_request)

    assert response == error_redirect
