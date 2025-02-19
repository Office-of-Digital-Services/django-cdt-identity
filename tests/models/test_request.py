from django.core.exceptions import ValidationError

import pytest

from cdt_identity.models import ClaimsVerificationRequest
from cdt_identity.routes import Routes


@pytest.fixture
def config_data():
    return {
        "scopes": "one two",
        "eligibility_claim": "test-claim",
        "extra_claims": "three four five",
        "scheme": "bearer-override",
        "redirect_fail": "test:fail",
        "redirect_success": "test:success",
        "redirect_post_logout": "test:logout",
    }


@pytest.mark.django_db
def test_create(config_data):
    req = ClaimsVerificationRequest.objects.create(**config_data)

    assert req.scopes == config_data["scopes"]
    assert req.eligibility_claim == config_data["eligibility_claim"]
    assert req.extra_claims == config_data["extra_claims"]
    assert req.scheme == config_data["scheme"]
    assert req.redirect_fail == config_data["redirect_fail"]
    assert req.redirect_success == config_data["redirect_success"]
    assert req.redirect_post_logout == config_data["redirect_post_logout"]


@pytest.mark.django_db
@pytest.mark.parametrize(
    "field_name,max_length",
    [
        ("scopes", 200),
        ("eligibility_claim", 50),
        ("extra_claims", 200),
        ("scheme", 50),
        ("redirect_fail", 50),
        ("redirect_success", 50),
        ("redirect_post_logout", 50),
    ],
)
def test_max_length(config_data, field_name, max_length):
    config_data[field_name] = "x" * (max_length + 1)
    with pytest.raises(ValidationError):
        req = ClaimsVerificationRequest(**config_data)
        req.full_clean()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "field_name",
    [
        "scopes",
        "eligibility_claim",
        "redirect_fail",
        "redirect_success",
        "redirect_post_logout",
    ],
)
def test_not_blank(config_data, field_name):
    config_data[field_name] = ""
    with pytest.raises(ValidationError):
        req = ClaimsVerificationRequest(**config_data)
        req.full_clean()


@pytest.mark.django_db
@pytest.mark.parametrize(
    "field_name,default",
    [
        ("extra_claims", ""),
        ("scheme", ""),
        ("redirect_fail", Routes.route_verify_fail),
        ("redirect_success", Routes.route_verify_success),
        ("redirect_post_logout", Routes.route_post_logout),
    ],
)
def test_default(config_data, field_name, default):
    config_data.pop(field_name)
    req = ClaimsVerificationRequest.objects.create(**config_data)

    assert getattr(req, field_name) == default


@pytest.mark.django_db
@pytest.mark.parametrize(
    "eligibility_claim,extra_claims,expected",
    [
        ("   claim1   ", "", "claim1"),
        ("claim1", "    claim2   ", "claim1 claim2"),
        ("claim1", "claim2 claim3", "claim1 claim2 claim3"),
    ],
)
def test_all_claims(eligibility_claim, extra_claims, expected):
    req = ClaimsVerificationRequest.objects.create(eligibility_claim=eligibility_claim, extra_claims=extra_claims)

    assert req.all_claims == expected
