import pytest

from cdt_identity.claims import ClaimsResult, ClaimsParser


@pytest.mark.parametrize(
    "userinfo,expected_claims,verified_claims,errors",
    [
        # numeric flags
        (
            {"claim1": "1", "claim2": "0", "claim3": "15", "claim4": "-1"},
            ["claim1", "claim2", "claim3", "claim4"],
            {"claim1": True},
            {"claim3": 15},
        ),
        # boolean strings
        (
            {"claim1": "true", "claim2": "TRUE", "claim3": "false", "claim4": "FALSE"},
            ["claim1", "claim2", "claim3", "claim4"],
            {"claim1": True, "claim2": True},
            {},
        ),
        # string values
        (
            {"claim1": "not_a_number", "claim2": "$peci@l"},
            ["claim1", "claim2"],
            {"claim1": "not_a_number", "claim2": "$peci@l"},
            {},
        ),
        # missing values
        (
            {"claim1": "true", "claim3": "1"},
            ["claim1", "claim2"],
            {"claim1": True},
            {},
        ),
    ],
)
def test_ClaimsParser_parse(userinfo, expected_claims, verified_claims, errors):
    claims = ClaimsParser().parse(userinfo, expected_claims)

    assert isinstance(claims, ClaimsResult)
    assert claims.verified == verified_claims
    assert claims.errors == errors

    for key, value in verified_claims.items():
        assert claims[key] == value
        assert claims.get(key) == value
        assert key in claims
