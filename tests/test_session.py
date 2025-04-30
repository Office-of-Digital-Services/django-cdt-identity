from uuid import uuid4

import pytest
from django.http import HttpRequest

from cdt_identity.claims import ClaimsResult
from cdt_identity.models import IdentityGatewayConfig, ClaimsVerificationRequest
from cdt_identity.session import Session


@pytest.fixture
def mock_request(mocker):
    request = mocker.MagicMock(spec=HttpRequest)
    request.session = {"session_id": 123}
    return request


@pytest.fixture
def client_config():
    client_config = IdentityGatewayConfig.objects.create(
        client_name="name", client_id=uuid4(), authority="http://example.com", scheme="scheme"
    )
    yield client_config
    client_config.delete()


@pytest.fixture
def claims_request():
    request = ClaimsVerificationRequest.objects.create()
    yield request
    request.delete()


@pytest.fixture
def claims_result():
    return ClaimsResult(verified=True)


@pytest.mark.django_db
def test_init(mock_request):
    session = Session(mock_request)
    assert session.request == mock_request
    assert session.session == mock_request.session
    assert session.client_config is None
    assert session.claims_request is None
    assert session.claims_result == ClaimsResult()


@pytest.mark.django_db
def test_init_with_args(mock_request, client_config, claims_request, claims_result):
    session = Session(mock_request, client_config=client_config, claims_request=claims_request, claims_result=claims_result)
    assert session.client_config == client_config
    assert session.claims_request == claims_request
    assert session.claims_result == claims_result

    session = Session(mock_request, reset=True)
    assert session.client_config is None
    assert session.claims_request is None
    assert session.claims_result == ClaimsResult()


@pytest.mark.django_db
def test_client(mock_request, client_config):
    session = Session(mock_request)
    assert session.client_config is None

    session.client_config = client_config
    assert session.session[session._keys_client] == str(client_config.id)

    session.client_config = None
    assert session.session[session._keys_client] is None


@pytest.mark.django_db
def test_claims_request(mock_request, claims_request):
    session = Session(mock_request)
    assert session.claims_request is None

    session.claims_request = claims_request
    assert session.session[session._keys_request] == str(claims_request.id)

    session.claims_request = None
    assert session.session[session._keys_request] is None


def test_has_verified_claims(mock_request, claims_result):
    session = Session(mock_request, claims_result=claims_result)
    assert session.has_verified_claims()

    session.claims_result = ClaimsResult()
    assert not session.has_verified_claims()


@pytest.mark.django_db
def test_has_verified_eligibility_True(mock_request, claims_request):
    claims_request.eligibility_claim = "claim"
    claims_request.save()
    result = ClaimsResult(verified={"claim": True})

    assert Session(mock_request, claims_request=claims_request, claims_result=result).has_verified_eligibility()


@pytest.mark.django_db
def test_has_verified_eligibility_False(mock_request, claims_request, claims_result):
    # default session
    assert not Session(mock_request).has_verified_eligibility()

    # None request
    assert not Session(mock_request, claims_result=claims_result).has_verified_eligibility()

    # None result
    claims_request.eligibility_claim = "claim"
    claims_request.save()
    assert not Session(mock_request, claims_request=claims_request).has_verified_eligibility()
